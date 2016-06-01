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
// 4) Finally, fila data must be released from mempool file_capture_release()

#include "file_api.h"
#include "file_lib.h"
#include "file_mempool.h"

struct FileCaptureBlock
{
    uint32_t length;
    FileCaptureBlock* next;  /* next block of file data */
};

class FileCapture
{
public:
    FileCapture();
    ~FileCapture();

    // this must be called during snort init
    static void init_mempool(int64_t max_file_mem, int64_t block_size);

    // Capture file data to local buffer
    // This is the main function call to enable file capture
    FileCaptureState process_buffer(const uint8_t* file_data, int data_size,
        FilePosition pos);

    // Stop file capture, memory resource will be released if not reserved
    void stop();

    // Preserve the file in memory until it is released
    FileCaptureState reserve_file(FileContext* context);

    // Get the file that is reserved in memory, this should be called repeatedly
    // until NULL is returned to get the full file
    // Returns:
    //   the next memory block
    //   NULL: end of file or fail to get file
    FileCaptureBlock* get_file_data(uint8_t** buff, int* size);

    // Get the file size captured in the file buffer
    // Returns:
    //   the size of file
    uint64_t capture_size() const;

    // Store files on local disk
    void store_file(FileContext *file);

    // Release the file that is reserved in memory, this function might be
    // called in a different thread.
    void release_file();

    // Log file capture mempool usage
    static void print_mem_usage();

    // Exit file capture, release all file capture memory etc,
    // this must be called when snort exits
    static void exit();

private:

    inline FileCaptureBlock* create_file_buffer(FileMemPool* file_mempool);
    inline FileCaptureState save_to_file_buffer(FileMemPool* file_mempool,
         const uint8_t* file_data, int data_size, int64_t max_size);
    void write_file(uint8_t *buf, size_t buf_len, FILE *fh);

    bool reserved;
    uint64_t file_size; /*file_size*/
    FileCaptureBlock* last;  /* last block of file data */
    FileCaptureBlock* head;  /* first block of file data */
    FileCaptureBlock* current_block = nullptr;  /* current block of file data */
    const uint8_t *current_data;  /*current file data*/
    uint32_t current_data_len;
    FileCaptureState capture_state;
};

typedef struct _File_Capture_Stats
{
    uint64_t files_buffered_total;
    uint64_t files_released_total;
    uint64_t files_freed_total;
    uint64_t files_captured_total;
    uint64_t file_memcap_failures_total;
    uint64_t file_memcap_failures_reserve; /*This happens during reserve*/
    uint64_t file_reserve_failures;        /*This happens during reserve*/
    uint64_t file_size_min;                /*This happens during reserve*/
    uint64_t file_size_max;                /*This happens during reserve*/
    uint64_t file_within_packet;
    uint64_t file_buffers_used_max;   /* maximum buffers used simultaneously*/
    uint64_t file_buffers_allocated_total;
    uint64_t file_buffers_freed_total;
    uint64_t file_buffers_released_total;
    uint64_t file_buffers_free_errors;
    uint64_t file_buffers_release_errors;
} File_Capture_Stats;

extern File_Capture_Stats file_capture_stats;

#endif

