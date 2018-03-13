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

// file_capture.h author Hui Cao <huica@cisco.com>

#ifndef FILE_CAPTURE_H
#define FILE_CAPTURE_H

// There are several steps for file capture:
// 1) To improve performance, file data are stored in file mempool first by
//    calling file_capture_process() during file data processing.
// 2) If file capture is needed, file_capture_reserve() should be called to
//    allow file data remains in mempool. Even if a session is closed, the file
//     data will stay in the mempool.
// 3) Then file data can be read through file_capture_read()
// 4) Finally, file data must be released from mempool file_capture_release()

#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

#include "file_api.h"

namespace snort
{
class FileInfo;
}
class FileMemPool;

struct FileCaptureBlock
{
    uint32_t length;
    FileCaptureBlock* next;  /* next block of file data */
};

class FileCapture
{
public:
    FileCapture(int64_t capture_min_size, int64_t capture_max_size);
    ~FileCapture();

    // this must be called during snort init
    static void init(int64_t memcap, int64_t block_size);

    // Capture file data to local buffer
    // This is the main function call to enable file capture
    FileCaptureState process_buffer(const uint8_t* file_data, int data_size,
        FilePosition pos);

    // Preserve the file in memory until it is released
    FileCaptureState reserve_file(const snort::FileInfo*);

    // Get the file that is reserved in memory, this should be called repeatedly
    // until nullptr is returned to get the full file
    // Returns:
    //   the next memory block
    //   nullptr: end of file or fail to get file
    FileCaptureBlock* get_file_data(uint8_t** buff, int* size);

    // Store files on local disk
    void store_file();

    // Store file to disk asynchronously
    void store_file_async();

    // Log file capture mempool usage
    static void print_mem_usage();

    // Exit file capture, release all file capture memory etc,
    // this must be called when snort exits
    static void exit();

    static FileCaptureState error_capture(FileCaptureState);

    static int64_t get_block_size() { return capture_block_size; }

    snort::FileInfo* get_file_info() { return file_info; }

private:

    static void init_mempool(int64_t max_file_mem, int64_t block_size);
    static void writer_thread();
    inline FileCaptureBlock* create_file_buffer();
    inline FileCaptureState save_to_file_buffer(const uint8_t* file_data, int data_size,
        int64_t max_size);
    void write_file_data(uint8_t* buf, size_t buf_len, FILE* fh);

    static FileMemPool* file_mempool;
    static int64_t capture_block_size;
    static std::mutex capture_mutex;
    static std::condition_variable capture_cv;
    static std::thread* file_storer;
    static std::queue<FileCapture*> files_waiting;
    static bool running;

    uint64_t capture_size;
    FileCaptureBlock* last;  /* last block of file data */
    FileCaptureBlock* head;  /* first block of file data */
    FileCaptureBlock* current_block = nullptr;  /* current block of file data */
    const uint8_t* current_data;  /*current file data*/
    uint32_t current_data_len;
    FileCaptureState capture_state;
    snort::FileInfo* file_info = nullptr;
    int64_t capture_min_size;
    int64_t capture_max_size;
};

#endif

