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
#include "libs/file_lib.h"

struct FileCaptureInfo
{
    uint32_t length;
    bool reserved;
    FileCaptureInfo* last;  /* last block of file data */
    FileCaptureInfo* next;  /* next block of file data */
    uint64_t file_size; /*file_size*/
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
    uint64_t file_size_exceeded;
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

// this must be called during snort init
void file_capture_init_mempool(int64_t max_file_mem, int64_t block_size);

// Capture file data to local buffer
// This is the main function call to enable file capture
// Returns:
//   0: successful
//   1: fail to capture the file or file capture is disabled
int file_capture_process(FileContext* context,
    uint8_t* file_data, int data_size, FilePosition position);

// Stop file capture, memory resource will be released if not reserved
void file_capture_stop(FileContext* context);

// Preserve the file in memory until it is released
FileCaptureState file_capture_reserve(Flow* flow, FileCaptureInfo** file_mem);

// Get the file that is reserved in memory, this should be called repeatedly
// until NULL is returned to get the full file
// Returns:
//   the next memory block
//   NULL: end of file or fail to get file
FileCaptureInfo* file_capture_read(FileCaptureInfo* file_mem, uint8_t** buff, int* size);

// Get the file size captured in the file buffer
// Returns:
//   the size of file
//   0: no memory or fail to get file
size_t file_capture_size(FileCaptureInfo* file_mem);

// Release the file that is reserved in memory, this function might be
// called in a different thread.
void file_capture_release(FileCaptureInfo* data);

// Log file capture mempool usage
void file_capture_mem_usage(void);

// Exit file capture, release all file capture memory etc,
// this must be called when snort exits
 void file_caputure_close(void);

#endif

