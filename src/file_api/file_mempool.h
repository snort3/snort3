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

// file_mempool.h author Hui Cao <huica@cisco.com>

#ifndef FILE_MEMPOOL_H
#define FILE_MEMPOOL_H

//  This mempool implementation has very efficient alloc/free operations.
//  In addition, it provides thread-safe alloc/free for one allocation/free
//  thread and one release thread.
//  One more bonus: Double free detection is also added into this library
//  This is a thread safe version of memory pool for one writer and one reader thread

#include <mutex>

#include "main/snort_debug.h"

#include "circular_buffer.h"

#define FILE_MEM_SUCCESS    0  // FIXIT-L use bool
#define FILE_MEM_FAIL      (-1)

class FileMemPool
{
public:

    FileMemPool(uint64_t num_objects, size_t obj_size);
    ~FileMemPool();

    // Allocate a new object from the FileMemPool
    // Note: Memory block will not be zeroed for performance
    // Returns: a pointer to the FileMemPool object on success, nullptr on failure
    void* m_alloc();

    // This must be called by the same thread calling file_mempool_alloc()
    // Return: FILE_MEM_SUCCESS or FILE_MEM_FAIL
    int m_free(void* obj);

    // This can be called by a different thread calling file_mempool_alloc()
    // Return: FILE_MEM_SUCCESS or FILE_MEM_FAIL
    int m_release(void* obj);

    //Returns number of elements allocated
    uint64_t allocated();

    // Returns number of elements freed in current buffer
    uint64_t freed();

    // Returns number of elements released in current buffer
    uint64_t released();

    // Returns total number of elements in current buffer
    uint64_t total_objects() { return total; }

private:

    void free_pools();
    int remove(CircularBuffer* cb, void* obj);
#ifdef DEBUG_MSGS
    void verify();
#endif

    void** datapool; /* memory buffer */
    uint64_t total;
    CircularBuffer* free_list;
    CircularBuffer* released_list;
    size_t obj_size;
    std::mutex pool_mutex;
};

#endif

