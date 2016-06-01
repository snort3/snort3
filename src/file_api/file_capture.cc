//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "file_stats.h"

#include "main/snort_config.h"
#include "hash/hashes.h"
#include "utils/util.h"
#include "utils/stats.h"

FileMemPool* file_mempool = nullptr;
File_Capture_Stats file_capture_stats;

FileCapture::FileCapture()
{
    reserved = 0;
    file_size = 0;
    last = head = nullptr;
    current_data = nullptr;
    current_data_len = 0;
    capture_state = FILE_CAPTURE_SUCCESS;
}

FileCapture:: ~FileCapture()
{
    stop();
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
void FileCapture::init_mempool(int64_t max_file_mem, int64_t block_len)
{
    int64_t block_size = block_len + sizeof (FileCapture);

    /*Convert megabytes to bytes*/
    int64_t max_file_mem_in_bytes = max_file_mem * 1024 * 1024;

    if (block_size <= 0)
        return;

    if (block_size & 7)
        block_size += (8 - (block_size & 7));

    int max_files = max_file_mem_in_bytes / block_size;

    file_mempool = (FileMemPool*)snort_calloc(sizeof(FileMemPool));

    if ( file_mempool_init(file_mempool, max_files, block_size) != 0 )
    {
        FatalError("File capture: Could not initialize file buffer mempool.\n");
    }
}

/*
 * Stop file capture, memory resource will be released if not reserved
 *
 * Returns: NONE
 */
void FileCapture::stop()
{
    /*free mempool*/
    if (reserved)
        return;

    file_capture_stats.files_freed_total++;
    FileCaptureBlock* fileblock = head;
    while (fileblock)
    {
        if (file_mempool_free(file_mempool, fileblock) != FILE_MEM_SUCCESS)
            file_capture_stats.file_buffers_free_errors++;
        fileblock = fileblock->next;
        file_capture_stats.file_buffers_freed_total++;
    }

    head = last = nullptr;
}

/*
 * Create file buffer in file mempool
 *
 * Args:
 *   FileMemPool *file_mempool: file mempool
 *   FileContext* context: file context
 *
 * Returns:
 *   FileCapture *: memory block that starts with file capture information
 */
inline FileCaptureBlock* FileCapture::create_file_buffer(FileMemPool* file_mempool)
{
    FileCaptureBlock* fileBlock;
    uint64_t num_files_queued;

    fileBlock = (FileCaptureBlock*)file_mempool_alloc(file_mempool);

    if (fileBlock == nullptr)
    {
        FILE_DEBUG_MSGS("Failed to get file capture memory!\n");
        file_capture_stats.file_memcap_failures_total++;
        return nullptr;
    }

    file_capture_stats.file_buffers_allocated_total++;

    fileBlock->length = 0;
    fileBlock->next = nullptr;     /*Only one block initially*/

    num_files_queued = file_mempool_allocated(file_mempool);
    if (file_capture_stats.file_buffers_used_max < num_files_queued)
        file_capture_stats.file_buffers_used_max = num_files_queued;

    return fileBlock;
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
inline FileCaptureState FileCapture::save_to_file_buffer(FileMemPool* file_mempool,
    const uint8_t* file_data, int data_size, int64_t max_size)
{
    FileCaptureBlock* lastBlock = last;
    int64_t available_bytes;
    FileConfig& file_config =  snort_conf->file_config;

    if ( data_size + (int64_t)file_size > max_size)
    {
        FILE_DEBUG_MSGS("Exceeding max file capture size!\n");
        file_capture_stats.file_size_max++;
        capture_state = FILE_CAPTURE_MAX;
        return FILE_CAPTURE_MAX;
    }

    /* Check whether current file block can hold file data*/
    available_bytes = file_config.capture_block_size - lastBlock->length;

    if ( data_size > available_bytes)
    {
        FileCaptureBlock* new_block;
        const uint8_t* file_current = file_data;
        const uint8_t* file_end = file_data + data_size;

        /*can't hold all, use current block first*/
        memcpy((uint8_t*)lastBlock + lastBlock->length + sizeof (*lastBlock),
            file_current, available_bytes);

        lastBlock->length = file_config.capture_block_size;
        file_current += available_bytes;

        /* We can support any file capture block size */
        while (1)
        {
            /*get another block*/
            new_block = (FileCaptureBlock*)create_file_buffer(file_mempool);

            if (new_block == nullptr)
            {
                capture_state = FILE_CAPTURE_MEMCAP;
                return FILE_CAPTURE_MEMCAP;
            }

            last->next = new_block;
            last = new_block;

            /*Save data to the new block*/
            if (file_current + file_config.capture_block_size < file_end)
            {
                memcpy((uint8_t*)last + sizeof(*new_block),
                    file_current,  file_config.capture_block_size);
                new_block->length =  file_config.capture_block_size;
                file_current += file_config.capture_block_size;
            }
            else
            {
                memcpy((uint8_t*)last + sizeof(*new_block),
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

    file_size += data_size;

    return FILE_CAPTURE_SUCCESS;
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
FileCaptureState FileCapture::process_buffer(const uint8_t* file_data,
    int data_size, FilePosition position)
{
    FileConfig& file_config =  snort_conf->file_config;

    current_data = file_data;
    current_data_len = data_size;

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
        if (!head)
        {
            head = last = create_file_buffer(file_mempool);

            if (!head)
            {
                return FILE_CAPTURE_MEMCAP;
            }

            file_capture_stats.files_buffered_total++;
        }

        return (save_to_file_buffer(file_mempool, file_data, data_size,
                file_config.capture_max_size));
    }

    return FILE_CAPTURE_SUCCESS;
}

/*Helper function for error*/
static inline FileCaptureState ERROR_capture(FileCaptureState state)
{
    file_capture_stats.file_reserve_failures++;
    return state;
}

// Preserve the file in memory until it is released
FileCaptureState FileCapture::reserve_file(FileContext* context)
{
    uint64_t fileSize;

    FileConfig& file_config =  snort_conf->file_config;

    if (!context || !context->is_file_capture_enabled())
    {
        return ERROR_capture(FILE_CAPTURE_FAIL);
    }

    if (capture_state != FILE_CAPTURE_SUCCESS)
    {
        return ERROR_capture(capture_state);
    }

    FileCaptureBlock* fileInfo = head;

    /*
     * Note: file size is updated at this point
     */
    fileSize = context->get_file_size();

    if ( fileSize < (unsigned)file_config.capture_min_size)
    {
        file_capture_stats.file_size_min++;
        return ERROR_capture(FILE_CAPTURE_MIN);
    }

    if ( fileSize > (unsigned)file_config.capture_max_size)
    {
        file_capture_stats.file_size_max++;
        return ERROR_capture(FILE_CAPTURE_MAX);
    }

    /* Create a file buffer if it is not done yet,
     * This is the case for small file
     */
    if (!fileInfo && context->is_file_capture_enabled())
    {
        fileInfo  = create_file_buffer(file_mempool);

        if (!fileInfo)
        {
            file_capture_stats.file_memcap_failures_reserve++;
            return ERROR_capture(FILE_CAPTURE_MEMCAP);
        }

        file_capture_stats.files_buffered_total++;
        head = last = fileInfo;
    }

    if (!fileInfo)
    {
        return ERROR_capture(FILE_CAPTURE_MEMCAP);
    }

    /*Copy the last piece of file to file buffer*/
    if (save_to_file_buffer(file_mempool, current_data,
            current_data_len, file_config.capture_max_size) )
    {
        return ERROR_capture(capture_state);
    }

    file_capture_stats.files_captured_total++;

    reserved = true;
    current_block = head;

    context->config_file_capture(false);

    return FILE_CAPTURE_SUCCESS;
}

/*
 * Get the file that is reserved in memory
 *
 * Arguments:
 *   uint8_t **buff: address to store buffer address
 *   int *size: address to store size of file
 *
 * Returns:
 *   the next memory block that stores file and its metadata
 *   nullptr: no more file data or fail to get file
 */
FileCaptureBlock* FileCapture::get_file_data(uint8_t** buff, int* size)
{
    if (!buff||!size || (current_block == nullptr))
    {
        *size = 0;
        *buff = nullptr;
        return nullptr;
    }

    *buff = (uint8_t*)current_block + sizeof(*current_block);
    *size = current_block->length;

    current_block = current_block->next;
    return (current_block);
}

// Get the file size captured in the file buffer
uint64_t FileCapture::capture_size() const
{
    return file_size;
}

/*
 * Release the file that is reserved in memory, this function might be
 * called in a different thread.
 *
 * Arguments:
 *   void *data: the memory block that stores file and its metadata
 */
void FileCapture::release_file()
{
    reserved = false;

    file_capture_stats.files_released_total++;
    FileCaptureBlock* fileblock = head;

    while (fileblock)
    {
        if (file_mempool_release(file_mempool, fileblock) != FILE_MEM_SUCCESS)
            file_capture_stats.file_buffers_release_errors++;
        fileblock = fileblock->next;
        file_capture_stats.file_buffers_released_total++;
    }

    head = last = nullptr;
}

/*
 * writing file to the disk.
 *
 * In the case of interrupt errors, the write is retried, but only for a
 * finite number of times.
 */
void FileCapture::write_file(uint8_t* buf, size_t buf_len, FILE* fh)
{
    int max_retries = 3;
    size_t bytes_written = 0;
    int err;

    /* Nothing to write or nothing to write to */
    if ((buf == nullptr) || (fh == nullptr))
        return;

    /* writing several times */
    do
    {
        size_t bytes_left = buf_len - bytes_written;

        bytes_written += fwrite(buf + bytes_written, 1, bytes_left, fh);

        err = ferror(fh);
        if (err && (err != EINTR) && (err != EAGAIN))
        {
            break;
        }

        max_retries--;
    }
    while ((max_retries > 0) && (bytes_written < buf_len));

    if (bytes_written < buf_len)
    {
        ErrorMessage("File inspect: disk writing error - %s!\n", get_error(err));
    }
}

// Store files on local disk
void FileCapture::store_file(FileContext* file)
{
    uint8_t* sha = file->get_file_sig_sha256();
    if (!sha)
        return;

    std::string file_name = file->sha_to_string(sha);

    std::string file_full_name;
    get_instance_file(file_full_name, file_name.c_str());

    /*Check whether the file exists*/
    struct stat buffer;
    if (stat (file_full_name.c_str(), &buffer) == 0)
    {
        return;
    }

    FILE* fh = fopen(file_full_name.c_str(), "w");
    if (!fh )
    {
        return;
    }

    // Check the file buffer
    uint8_t* buff = nullptr;
    int size = 0;
    void* file_mem;

    do
    {
        file_mem = get_file_data(&buff, &size);
        // Get file from file buffer
        if (!buff || !size )
        {
            //file_inspect_stats.file_read_failures++;
            return;
        }

        write_file(buff, size, fh);
    }
    while (file_mem);

    fclose(fh);
}

/*Log file capture mempool usage*/
void FileCapture::print_mem_usage()
{
    if (file_mempool)
    {
        LogCount("Max buffers can allocate", file_mempool->total);
        LogCount("Buffers in use", file_mempool_allocated(file_mempool));
        LogCount("Buffers in free list", file_mempool_freed(file_mempool));
        LogCount("Buffers in release list", file_mempool_released(file_mempool));
    }
}

/*
 *  Release all file capture memory etc,
 *  this must be called when snort exits
 */
void FileCapture::exit()
{
    if (file_mempool_destroy(file_mempool) == 0)
    {
        snort_free(file_mempool);
        file_mempool = nullptr;
    }
}

