//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
 **  9.25.2012 - Initial Source Code. Hui Cao
 */

#ifndef FILE_CAPTURE_H
#define FILE_CAPTURE_H

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

/*
 * Initialize the file memory pool
 *
 * Arguments:
 *    int64_t max_file_mem: memcap in bytes
 *    int64_t block_size:  file block size
 *
 * Returns: NONE
 */
void file_capture_init_mempool(int64_t max_file_mem, int64_t block_size);

/*
 * Capture file data to local buffer
 * This is the main function call to enable file capture
 *
 * Arguments:
 *   FileContext* context: current file context
 *   uint8_t *file_data: current file data
 *   int data_size: current file data size
 *   FilePosition position: position of file data
 *
 * Returns:
 *   0: successful
 *   1: fail to capture the file or file capture is disabled
 */
int file_capture_process(FileContext* context,
    uint8_t* file_data, int data_size, FilePosition position);

/*
 * Stop file capture, memory resource will be released if not reserved
 *
 * Returns: NONE
 */
void file_capture_stop(FileContext* context);

/*
 * Preserve the file in memory until it is released
 *
 * Arguments:
 *   Flow *ssnptr: flow pointer
 *   FileCaptureInfo **file_mem: the pointer to store the memory block
 *       that stores file and its metadata.
 *       It will set  NULL if no memory or fail to store
 *
 * Returns:
 *   FileCaptureState:
 *      FILE_CAPTURE_SUCCESS = 0,
 *      FILE_CAPTURE_MIN,
 *      FILE_CAPTURE_MAX,
 *      FILE_CAPTURE_MEMCAP,
 *      FILE_CAPTURE_FAIL
 */
FileCaptureState file_capture_reserve(Flow* flow, FileCaptureInfo** file_mem);

/*
 * Get the file that is reserved in memory
 *
 * Arguments:
 *   FileCaptureInfo *file_mem: the memory block working on
 *   uint8_t **buff: address to store buffer address
 *   int *size: address to store size of file
 *
 * Returns:
 *   the next memory block
 *   NULL: end of file or fail to get file
 */
FileCaptureInfo* file_capture_read(FileCaptureInfo* file_mem, uint8_t** buff, int* size);

/*
 * Get the file size captured in the file buffer
 *
 * Arguments:
 *   FileCaptureInfo *file_mem: the first memory block of file buffer
 *
 * Returns:
 *   the size of file
 *   0: no memory or fail to get file
 */
size_t file_capture_size(FileCaptureInfo* file_mem);

/*
 * Release the file that is reserved in memory, this function might be
 * called in a different thread.
 *
 * Arguments:
 *   FileCaptureInfo *data: the memory block that stores file and its metadata
 */
void file_capture_release(FileCaptureInfo* data);

/*Log file capture mempool usage*/

void file_capture_mem_usage(void);

/*
 *  Exit file capture, release all file capture memory etc,
 *  this must be called when snort exits
 */
void file_caputure_close(void);

#endif

