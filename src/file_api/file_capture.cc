//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_capture.h"

#include <sys/stat.h>

#include <cassert>

#include "log/messages.h"
#include "utils/stats.h"
#include "utils/util.h"

#include "file_mempool.h"
#include "file_stats.h"

using namespace snort;

FileMemPool* FileCapture::file_mempool = nullptr;
int64_t FileCapture::capture_block_size = 0;

std::mutex FileCapture::capture_mutex;
std::condition_variable FileCapture::capture_cv;
std::thread* FileCapture::file_storer = nullptr;
std::queue<FileCapture*> FileCapture::files_waiting;
bool FileCapture::running = true;

FileCaptureState FileCapture::error_capture(FileCaptureState state)
{
    file_counts.file_reserve_failures++;
    return state;
}

// Only one writer thread supported
void FileCapture::writer_thread()
{
    while (true)
    {
        // Wait until there are files
        std::unique_lock<std::mutex> lk(capture_mutex);
        capture_cv.wait(lk, [] { return !running or !files_waiting.empty(); });

        // When !running we write out any remaining files before exiting.
        // FIXIT-L should take dirty_pig into account. But this thread does not have convenient
        // access to snort_conf.
        if (files_waiting.empty())
            break;

        FileCapture* file = files_waiting.front();
        files_waiting.pop();
        lk.unlock();

        file->store_file();
        delete file;
    }
}

FileCapture::FileCapture(int64_t min_size, int64_t max_size)
{
    capture_size = 0;
    last = head = nullptr;
    current_data = nullptr;
    current_data_len = 0;
    capture_state = FILE_CAPTURE_SUCCESS;
    capture_min_size = min_size;
    capture_max_size = max_size;
}

FileCapture::~FileCapture()
{
    FileCaptureBlock* file_block = head;

    if (file_info)
        file_counts.files_released_total++;
    else
        file_counts.files_freed_total++;

    while (file_block)
    {
        FileCaptureBlock* next_block = file_block->next;
        if (file_info)
        {
            if (file_mempool->m_release(file_block) != FILE_MEM_SUCCESS)
                file_counts.file_buffers_release_errors++;
            file_counts.file_buffers_released_total++;
        }
        else
        {
            if (file_mempool->m_free(file_block) != FILE_MEM_SUCCESS)
                file_counts.file_buffers_free_errors++;
            file_counts.file_buffers_freed_total++;
        }

        file_block = next_block;
    }

    head = last = nullptr;

    if (file_info)
        delete file_info;
}

void FileCapture::init(int64_t memcap, int64_t block_size)
{
    capture_block_size = block_size;
    init_mempool(memcap, capture_block_size);
    file_storer = new std::thread(writer_thread);
}

/*
 *  Release all file capture memory etc,
 *  this must be called when snort exits
 */
void FileCapture::exit()
{
    {
        std::lock_guard<std::mutex> lk(capture_mutex);
        running = false;
    }
    capture_cv.notify_one();

    if (file_storer)
    {
        file_storer->join();
        delete file_storer;
        file_storer = nullptr;
    }

    if (file_mempool)
    {
        delete file_mempool;
        file_mempool = nullptr;
    }
}

/*
 * Initialize the file memory pool
 *
 * Arguments:
 *    int64_t max_file_mem: memcap in megabytes
 *    int64_t block_len:  file block size (metadata size excluded)
 */
void FileCapture::init_mempool(int64_t max_file_mem, int64_t block_len)
{
    int64_t block_size = block_len + sizeof (FileCapture);

    if (block_size <= 0)
        return;

    /*Convert megabytes to bytes*/
    int64_t max_file_mem_in_bytes = max_file_mem * 1024 * 1024;

    if (block_size & 7)
        block_size += (8 - (block_size & 7));

    int max_files = max_file_mem_in_bytes / block_size;

    file_mempool = new FileMemPool(max_files, block_size);
}

inline FileCaptureBlock* FileCapture::create_file_buffer()
{
    FileCaptureBlock* fileBlock;
    uint64_t num_files_queued;

    fileBlock = (FileCaptureBlock*)file_mempool->m_alloc();

    if (fileBlock == nullptr)
    {
        file_counts.file_memcap_failures_total++;
        return nullptr;
    }

    file_counts.file_buffers_allocated_total++;

    fileBlock->length = 0;
    fileBlock->next = nullptr;     /*Only one block initially*/

    num_files_queued = file_mempool->allocated();
    if (file_counts.file_buffers_used_max < num_files_queued)
        file_counts.file_buffers_used_max = num_files_queued;

    return fileBlock;
}

/*
 * Save file to the buffer
 * If file needs to be extracted, buffer will be reserved
 * If file buffer isn't sufficient, need to add another buffer.
 */
inline FileCaptureState FileCapture::save_to_file_buffer(const uint8_t* file_data,
    int data_size, int64_t max_size)
{
    FileCaptureBlock* lastBlock = last;
    int64_t available_bytes;

    if ( data_size + (int64_t)capture_size > max_size)
    {
        file_counts.file_size_max++;
        capture_state = FILE_CAPTURE_MAX;
        return FILE_CAPTURE_MAX;
    }

    /* Check whether current file block can hold file data*/
    available_bytes = capture_block_size - lastBlock->length;

    if ( data_size > available_bytes)
    {
        FileCaptureBlock* new_block;
        const uint8_t* file_current = file_data;
        const uint8_t* file_end = file_data + data_size;

        /*can't hold all, use current block first*/
        memcpy((uint8_t*)lastBlock + lastBlock->length + sizeof (*lastBlock),
            file_current, available_bytes);

        lastBlock->length = capture_block_size;
        file_current += available_bytes;

        /* We can support any file capture block size */
        while (true)
        {
            /*get another block*/
            new_block = (FileCaptureBlock*)create_file_buffer();

            if (new_block == nullptr)
            {
                capture_state = FILE_CAPTURE_MEMCAP;
                return FILE_CAPTURE_MEMCAP;
            }

            last->next = new_block;
            last = new_block;

            /*Save data to the new block*/
            if (file_current + capture_block_size < file_end)
            {
                memcpy((uint8_t*)last + sizeof(*new_block),
                    file_current,  capture_block_size);
                new_block->length =  capture_block_size;
                file_current += capture_block_size;
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

    capture_size += data_size;

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
    current_data = file_data;
    current_data_len = data_size;

    switch (position)
    {
    case SNORT_FILE_FULL:
        file_counts.file_within_packet++;
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
            head = last = create_file_buffer();

            if (!head)
            {
                return FILE_CAPTURE_MEMCAP;
            }

            file_counts.files_buffered_total++;
        }

        return (save_to_file_buffer(file_data, data_size, capture_max_size));
    }

    return FILE_CAPTURE_SUCCESS;
}

// Preserve the file in memory until it is released
FileCaptureState FileCapture::reserve_file(const FileInfo* file)
{
    uint64_t fileSize;

    if (capture_state != FILE_CAPTURE_SUCCESS)
    {
        return error_capture(capture_state);
    }

    FileCaptureBlock* fileBlock = head;

    /*
     * Note: file size is updated at this point
     */
    fileSize = file->get_file_size();

    if ( fileSize < (unsigned)capture_min_size)
    {
        file_counts.file_size_min++;
        return error_capture(FILE_CAPTURE_MIN);
    }

    if ( fileSize > (unsigned)capture_max_size)
    {
        file_counts.file_size_max++;
        return error_capture(FILE_CAPTURE_MAX);
    }

    /* Create a file buffer if it is not done yet,
     * This is the case for small file
     */
    if (!fileBlock)
    {
        fileBlock  = create_file_buffer();

        if (!fileBlock)
        {
            file_counts.file_memcap_failures_reserve++;
            return error_capture(FILE_CAPTURE_MEMCAP);
        }

        file_counts.files_buffered_total++;
        head = last = fileBlock;
    }

    if (!fileBlock)
    {
        return error_capture(FILE_CAPTURE_MEMCAP);
    }

    /*Copy the last piece of file to file buffer*/
    if (save_to_file_buffer(current_data,
            current_data_len, capture_max_size) )
    {
        return error_capture(capture_state);
    }

    file_counts.files_captured_total++;

    current_block = head;

    file_info = new FileInfo(*file);

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
    assert(buff && size);
    if (current_block == nullptr)
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

/*
 * writing file data to the disk.
 *
 * In the case of interrupt errors, the write is retried, but only for a
 * finite number of times.
 */
void FileCapture::write_file_data(uint8_t* buf, size_t buf_len, FILE* fh)
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
void FileCapture::store_file()
{
    if (!file_info)
        return;

    std::string& file_full_name = file_info->get_file_name();

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
            return;
        }

        write_file_data(buff, size, fh);
    }
    while (file_mem);

    fclose(fh);
}

// Queue files to be stored to disk
void FileCapture::store_file_async()
{
    // send data to the writer thread
    if (!file_info)
        return;

    uint8_t* sha = file_info->get_file_sig_sha256();
    if (!sha)
        return;

    std::string file_name = file_info->sha_to_string(sha);

    std::string file_full_name;
    get_instance_file(file_full_name, file_name.c_str());
    file_info->set_file_name(file_full_name.c_str(), file_full_name.size());

    std::lock_guard<std::mutex> lk(capture_mutex);
    files_waiting.push(this);
    capture_cv.notify_one();
}

/*Log file capture mempool usage*/
void FileCapture::print_mem_usage()
{
    if (file_mempool)
    {
        LogCount("Max buffers can allocate", file_mempool->total_objects());
        LogCount("Buffers in use", file_mempool->allocated());
        LogCount("Buffers in free list", file_mempool->freed());
        LogCount("Buffers in release list", file_mempool->released());
    }
}

