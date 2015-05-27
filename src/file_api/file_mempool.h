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
 **  This mempool implementation has very efficient alloc/free operations.
 **  In addition, it provides thread-safe alloc/free for one allocation/free
 **  thread and one release thread.
 **  One more bonus: Double free detection is also added into this library
 **
 **  NOTES
 **  5.25.13 - Initial Source Code. Hui Cao
 **
 **  This is a thread safe version of memory pool for one writer and one reader thread
 */

#ifndef FILE_MEMPOOL_H
#define FILE_MEMPOOL_H

#include "snort_types.h"
#include "circular_buffer.h"

#define FILE_MEM_SUCCESS   0
#define FILE_MEM_FAIL      -1

typedef struct _FileMemPool
{
    void** datapool; /* memory buffer */

    uint64_t total;

    CircularBuffer* free_list;
    CircularBuffer* released_list;
    size_t obj_size;
} FileMemPool;

/* Initialize mempool
 *
 * Args:
 *   FileMemPool: pointer to a FileMemPool struct
 *   uint64_t num_objects: number of objects
 *   size_t obj_size: size of object
 *
 * Return:
 *   FILE_MEM_SUCCESS
 *   FILE_MEM_FAIL
 */
int file_mempool_init(FileMemPool* mempool, uint64_t num_objects,
    size_t obj_size);

/* Free mempool memory objects
 *
 * Args:
 *   FileMemPool: pointer to a FileMemPool struct
 *
 * Return:
 *   FILE_MEM_SUCCESS
 *   FILE_MEM_FAIL
 */
int file_mempool_destroy(FileMemPool* mempool);

/*
 * Allocate a new object from the FileMemPool
 * Memory block will not be zeroed for performance
 *
 * Args:
 *   FileMemPool: pointer to a FileMemPool struct
 *
 * Returns: a pointer to the FileMemPool object on success, NULL on failure
 */
void* file_mempool_alloc(FileMemPool* mempool);

/*
 * Free a new object from the FileMemPool
 * This must be called by the same thread calling
 * file_mempool_alloc()
 *
 * Args:
 *   FileMemPool: pointer to a FileMemPool struct
 *   void *obj  : memory object
 *
 * Return:
 *   FILE_MEM_SUCCESS
 *   FILE_MEM_FAIL
 */
int file_mempool_free(FileMemPool* mempool, void* obj);

/*
 * Release a new object from the FileMemPool
 * This can be called by a different thread calling
 * file_mempool_alloc()
 *
 * Args:
 *   FileMemPool: pointer to a FileMemPool struct
 *   void *obj  : memory object
 *
 * Return:
 *   FILE_MEM_SUCCESS
 *   FILE_MEM_FAIL
 */
int file_mempool_release(FileMemPool* mempool, void* obj);

/* Returns number of elements allocated in current buffer*/
uint64_t file_mempool_allocated(FileMemPool* mempool);

/* Returns number of elements freed in current buffer*/
uint64_t file_mempool_freed(FileMemPool* mempool);

/* Returns number of elements released in current buffer*/
uint64_t file_mempool_released(FileMemPool* mempool);

#endif

