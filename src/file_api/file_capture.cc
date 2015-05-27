//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
/*
 **
 **  Author(s):  Hui Cao <huica@cisco.com>
 **
 **  NOTES
 **  5.05.2013 - Initial Source Code. Hui Cao
 */

#include "file_capture.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_types.h"
#include "file_service.h"
#include "file_mempool.h"
#include "util.h"
#include <sys/stat.h>
//#include "sf_sechash.h"
#include "snort.h"
#include "stream/stream_api.h"
#include "libs/file_config.h"
#include "file_stats.h"

#include "hash/hashes.h"
#include "main/snort_config.h"
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>

// FIXIT-L these are no longer needed
#define SHA256CONTEXT SHA256_CTX
#define SHA256INIT    SHA256_Init
#define SHA256UPDATE  SHA256_Update
#define SHA256FINAL   SHA256_Final

FileMemPool* file_mempool = NULL;
File_Capture_Stats file_capture_stats;

/*
 * Verify file capture information and file context information matched
 * This is used for debug purpose
 */

#ifdef DEBUG
static void verify_file_capture_info(FileContext* context,
    FileCaptureInfo* fileInfo)
{
    /* file capture length should be one of two possible values */
    if (context->processed_bytes)
    {
        if ((fileInfo->file_size != context->processed_bytes) &&
            (fileInfo->file_size + context->current_data_len
                != context->processed_bytes))
        {
            FILE_DEBUG_MSGS("File capture size failed w.r.t processed size!\n");
        }
    }
    else
    {
        if ((fileInfo->file_size != context->file_size) &&
            (fileInfo->file_size + context->current_data_len
                != context->file_size))
        {
            FILE_DEBUG_MSGS("File capture size failed w.r.t final file size!\n");
        }
    }
}

static void verifiy_file_capture(FileContext* context,
    FileCaptureInfo* fileInfo)
{
    SHA256CONTEXT sha_ctx;
    uint8_t* buff;
    int size;
    FileCaptureInfo* file_mem = fileInfo;
    uint8_t sha256[SHA256_HASH_SIZE + 1];
    int i;

    memset(&sha_ctx, 0, sizeof(sha_ctx));

    /*Calculator the SHA*/
    SHA256INIT(&sha_ctx);

    while (file_mem)
    {
        file_mem = file_capture_read(file_mem, &buff, &size);
        SHA256UPDATE(&sha_ctx, buff, size);
    }

    SHA256FINAL(sha256, &sha_ctx);

    for (i = 0; i < SHA256_HASH_SIZE; i++)
    {
        if (sha256[i] != context->sha256[i])
        {
            FILE_DEBUG_MSGS("File capture buffer is wrong!\n");
            break;
        }
    }
}

#endif

/*
 * Initialize the file memory pool
 *
 * Returns:
 *   void *: pointer to mempool
 *   NULL  : fail to initialize file mempool
 */
static FileMemPool* _init_file_mempool(int64_t max_file_mem, int64_t block_size)
{
    int max_files;
    FileMemPool* file_mempool;
    int64_t max_file_mem_in_bytes;

    /*Convert megabytes to bytes*/
    max_file_mem_in_bytes = max_file_mem * 1024 * 1024;

    if (block_size <= 0)
        return NULL;

    if (block_size & 7)
        block_size += (8 - (block_size & 7));

    max_files = max_file_mem_in_bytes / block_size;

    file_mempool = (FileMemPool*)calloc(1, sizeof(FileMemPool));

    if ((!file_mempool)||
        (file_mempool_init(file_mempool, max_files, block_size) != 0))
    {
        FatalError("File capture: Could not allocate file buffer mempool.\n");
    }

    return file_mempool;
}

/*
 * Initialize the file memory pool
 *
 * Arguments:
 *    int64_t max_file_mem: memcap in megabytes
 *    int64_t block_size:  file block size (metadata size excluded)
 *
 * Returns: NONE
 */
void file_capture_init_mempool(int64_t max_file_mem, int64_t block_size)
{
    int64_t metadata_size = sizeof (FileCaptureInfo);

    file_mempool = _init_file_mempool(max_file_mem, block_size + metadata_size);
}

/* Free file buffer list*/
static inline void _free_file_buffer(FileCaptureInfo* fileInfo)
{
    file_capture_stats.files_freed_total++;

    while (fileInfo)
    {
        if (file_mempool_free(file_mempool, fileInfo) != FILE_MEM_SUCCESS)
            file_capture_stats.file_buffers_free_errors++;
        fileInfo = fileInfo->next;
        file_capture_stats.file_buffers_freed_total++;
    }
}

/* Release file buffer list*/
static inline void _release_file_buffer(FileCaptureInfo* fileInfo)
{
    file_capture_stats.files_released_total++;

    while (fileInfo)
    {
        if (file_mempool_release(file_mempool, fileInfo) != FILE_MEM_SUCCESS)
            file_capture_stats.file_buffers_release_errors++;
        fileInfo = fileInfo->next;
        file_capture_stats.file_buffers_released_total++;
    }
}

/*
 * Stop file capture, memory resource will be released if not reserved
 *
 * Returns: NONE
 */
void file_capture_stop(FileContext* context)
{
    FileCaptureInfo* fileInfo = context->file_capture;

    if (fileInfo)
    {
        /*free mempool*/
        FILE_DEBUG_MSGS("Stop file capture!\n");
        if (!fileInfo->reserved)
        {
            _free_file_buffer(fileInfo);
        }
        context->file_capture = NULL;
    }
    context->file_capture_enabled = false;
}

/*
 * Create file buffer in file mempool
 *
 * Args:
 *   FileMemPool *file_mempool: file mempool
 *   FileContext* context: file context
 *
 * Returns:
 *   FileCaptureInfo *: memory block that starts with file capture information
 */
static inline FileCaptureInfo* _create_file_buffer(FileMemPool* file_mempool)
{
    FileCaptureInfo* fileInfo;
    uint64_t num_files_queued;

    fileInfo = (FileCaptureInfo*)file_mempool_alloc(file_mempool);

    if (fileInfo == NULL)
    {
        FILE_DEBUG_MSGS("Failed to get file capture memory!\n");
        file_capture_stats.file_memcap_failures_total++;
        return NULL;
    }

    file_capture_stats.file_buffers_allocated_total++;

    fileInfo->length = 0;
    fileInfo->reserved = false;
    fileInfo->next = NULL;     /*Only one block initially*/
    fileInfo->last = fileInfo;
    fileInfo->file_size = 0;

    num_files_queued = file_mempool_allocated(file_mempool);
    if (file_capture_stats.file_buffers_used_max < num_files_queued)
        file_capture_stats.file_buffers_used_max = num_files_queued;

    return fileInfo;
}

/*
 * Save file to the buffer
 * If file needs to be extracted, buffer will be reserved
 * If file buffer isn't sufficient, need to add another buffer.
 *
 * Returns:
 *   0: successful or file capture is disabled
 *   1: fail to capture the file
 */
static inline int _save_to_file_buffer(FileMemPool* file_mempool,
    FileContext* context, uint8_t* file_data, int data_size,
    int64_t max_size)
{
    FileCaptureInfo* fileInfo = (FileCaptureInfo*)context->file_capture;
    FileCaptureInfo* lastBlock = fileInfo->last;
    int64_t available_bytes;
    FileConfig* file_config =  (FileConfig*)(snort_conf->file_config);

    DEBUG_WRAP(verify_file_capture_info(context, fileInfo); );

    if ( data_size + (signed)fileInfo->file_size > max_size)
    {
        FILE_DEBUG_MSGS("Exceeding max file capture size!\n");
        file_capture_stats.file_size_exceeded++;
        context->file_state.capture_state = FILE_CAPTURE_MAX;
        return -1;
    }

    /* Check whether current file block can hold file data*/
    available_bytes = file_config->file_capture_block_size - lastBlock->length;

    if ( data_size > available_bytes)
    {
        FileCaptureInfo* new_block;
        uint8_t* file_current = file_data;
        uint8_t* file_end = file_data + data_size;

        /*can't hold all, use current block first*/
        memcpy((uint8_t*)lastBlock + lastBlock->length + sizeof (*lastBlock),
            file_current, available_bytes);

        lastBlock->length = file_config->file_capture_block_size;
        file_current += available_bytes;

        /* We can support any file capture block size */
        while (1)
        {
            /*get another block*/
            new_block = (FileCaptureInfo*)_create_file_buffer(file_mempool);

            if (new_block == NULL)
            {
                context->file_state.capture_state = FILE_CAPTURE_MEMCAP;
                return -1;
            }

            fileInfo->last->next = new_block;
            fileInfo->last = new_block;

            /*Save data to the new block*/
            if (file_current + file_config->file_capture_block_size < file_end)
            {
                memcpy((uint8_t*)fileInfo->last + sizeof(*new_block),
                    file_current,  file_config->file_capture_block_size);
                new_block->length =  file_config->file_capture_block_size;
                file_current += file_config->file_capture_block_size;
            }
            else
            {
                memcpy((uint8_t*)fileInfo->last + sizeof(*new_block),
                    file_current,  file_end - file_current);

                new_block->length = file_end - file_current;
                break;
            }
        }
    }
    else
    {
        memcpy((uint8_t*)lastBlock + lastBlock->length + sizeof(*lastBlock),
            file_data, data_size);

        lastBlock->length += data_size;
    }

    fileInfo->file_size += data_size;

    DEBUG_WRAP(verify_file_capture_info(context, fileInfo); )
    return 0;
}

/*
 * Save files to the local buffer first for files transferred
 * by multiple reassembled packets. For files within a packet,
 * simply using the packet buffer.
 * If file needs to be extracted, buffer will be reserved
 *
 * Arguments:
 *   FileContext* context: current file context
 *   uint8_t *file_data: current file data
 *   int data_size: current file data size
 *   FilePosition position: position of file data
 * Returns:
 *   0: successful
 *   1: fail to capture the file or file capture is disabled
 */
int file_capture_process(FileContext* context, uint8_t* file_data,
    int data_size, FilePosition position)
{
    FileCaptureInfo* fileInfo = (FileCaptureInfo*)context->file_capture;
    FileConfig* file_config =  (FileConfig*)(snort_conf->file_config);

    context->current_data = file_data;
    context->current_data_len = data_size;

    switch (position)
    {
    case SNORT_FILE_FULL:
        file_capture_stats.file_within_packet++;
        break;
    case SNORT_FILE_END:
        break;
    default:

        /* For File position is either SNORT_FILE_START
         * or SNORT_FILE_MIDDLE,  the file is larger than one packet,
         * we need to store them into buffer.
         */

        if (!context->file_capture)
        {
            fileInfo  = _create_file_buffer(file_mempool);

            if (!fileInfo)
            {
                FILE_DEBUG_MSGS("Can't get file capture memory!\n");
                context->file_state.capture_state = FILE_CAPTURE_MEMCAP;
                return -1;
            }

            file_capture_stats.files_buffered_total++;

            context->file_capture = fileInfo;
        }

        if (!fileInfo)
        {
            return -1;
        }

        if (_save_to_file_buffer(file_mempool, context, file_data, data_size,
                file_config->file_capture_max_size))
        {
            FILE_DEBUG_MSGS("Can't save to file buffer!\n");
            return -1;
        }
    }

    return 0;
}

/*Helper function for error*/
static inline FileCaptureState ERROR_capture(FileCaptureState state)
{
    file_capture_stats.file_reserve_failures++;
    return state;
}

/*
 * Preserve the file in memory until it is released
 *
 * Arguments:
 *   void *ssnptr: session pointer
 *   void **file_mem: the pointer to store the memory block
 *       that stores file and its metadata.
 *       It will set  NULL if no memory or fail to store
 *
 * Returns:
 *   FileCaptureState
 *
 */
FileCaptureState file_capture_reserve(Flow* flow, FileCaptureInfo** file_mem)
{
    FileContext* context;
    FileCaptureInfo* fileInfo;
    uint64_t fileSize;
    FileConfig* file_config =  (FileConfig*)(snort_conf->file_config);

    if (!flow||!file_config||!file_mem)
    {
        return ERROR_capture(FILE_CAPTURE_FAIL);
    }

    context = get_current_file_context(flow);

    if (!context || !context->file_capture_enabled)
    {
        return ERROR_capture(FILE_CAPTURE_FAIL);
    }

    if (context->file_state.capture_state != FILE_CAPTURE_SUCCESS)
    {
        return ERROR_capture(context->file_state.capture_state);
    }

    fileInfo = (FileCaptureInfo*)(context->file_capture);

    /*
     * Note: file size is updated at this point
     */
    fileSize = context->file_size;

    if ( fileSize < (unsigned)file_config->file_capture_min_size)
    {
        file_capture_stats.file_size_min++;
        return ERROR_capture(FILE_CAPTURE_MIN);
    }

    if ( fileSize > (unsigned)file_config->file_capture_max_size)
    {
        file_capture_stats.file_size_max++;
        return ERROR_capture(FILE_CAPTURE_MAX);
    }

    /* Create a file buffer if it is not done yet,
     * This is the case for small file
     */
    if (!fileInfo && context->file_capture_enabled)
    {
        fileInfo  = _create_file_buffer(file_mempool);

        if (!fileInfo)
        {
            file_capture_stats.file_memcap_failures_reserve++;
            return ERROR_capture(FILE_CAPTURE_MEMCAP);
        }

        file_capture_stats.files_buffered_total++;
        context->file_capture = fileInfo;

        DEBUG_WRAP(verify_file_capture_info(context, fileInfo); );
    }

    if (!fileInfo)
    {
        return ERROR_capture(FILE_CAPTURE_MEMCAP);
    }

    DEBUG_WRAP(verify_file_capture_info(context, fileInfo); );

    /*Copy the last piece of file to file buffer*/
    if (_save_to_file_buffer(file_mempool, context, context->current_data,
            context->current_data_len, file_config->file_capture_max_size) )
    {
        return ERROR_capture(context->file_state.capture_state);
    }

    file_capture_stats.files_captured_total++;

    *file_mem = fileInfo;

    fileInfo->reserved = true;

    /* Clear file capture information on file context
     * Without this, the next file within the same session
     * might use this information to change shared memory buffer
     * that might be released and then used by other sessions
     */
    context->file_capture = NULL;
    context->file_capture_enabled = false;
    DEBUG_WRAP(verifiy_file_capture(context, fileInfo); );

    return FILE_CAPTURE_SUCCESS;
}

/*
 * Get the file that is reserved in memory
 *
 * Arguments:
 *   void *: the memory block that stores file and its metadata
 *   uint8_t **buff: address to store buffer address
 *   int *size: address to store size of file
 *
 * Returns:
 *   the next memory block that stores file and its metadata
 *   NULL: no more file data or fail to get file
 */
FileCaptureInfo* file_capture_read(FileCaptureInfo* fileInfo, uint8_t** buff, int* size)
{
    if (!fileInfo|!buff||!size)
    {
        return NULL;
    }

    *buff = (uint8_t*)fileInfo + sizeof(*fileInfo);
    *size = fileInfo->length;

    return (fileInfo->next);
}

/*
 * Get the file size captured in the file buffer
 *
 * Arguments:
 *   void *file_mem: the first memory block of file buffer
 *
 * Returns:
 *   the size of file
 *   0: not the first file block or fail to get file
 */
size_t file_capture_size(FileCaptureInfo* fileInfo)
{
    if (!fileInfo)
        return 0;

    return fileInfo->file_size;
}

/*
 * Release the file that is reserved in memory, this function might be
 * called in a different thread.
 *
 * Arguments:
 *   void *data: the memory block that stores file and its metadata
 */
void file_capture_release(FileCaptureInfo* fileInfo)
{
    if (!fileInfo)
        return;

    fileInfo->reserved = false;

    _release_file_buffer(fileInfo);
}

/*Log file capture mempool usage*/
void file_capture_mem_usage(void)
{
    if (file_mempool)
    {
        LogMessage("Maximum buffers can allocate:      " FMTu64("-10") " \n",
            file_mempool->total);
        LogMessage("Number of buffers in use:          " FMTu64("-10") " \n",
            file_mempool_allocated(file_mempool));
        LogMessage("Number of buffers in free list:    " FMTu64("-10") " \n",
            file_mempool_freed(file_mempool));
        LogMessage("Number of buffers in release list: " FMTu64("-10") " \n",
            file_mempool_released(file_mempool));
    }
}

/*
 *  Release all file capture memory etc,
 *  this must be called when snort exits
 */
void file_caputure_close(void)
{
    if (file_mempool_destroy(file_mempool) == 0)
    {
        free(file_mempool);
        file_mempool = NULL;
    }
}

