//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
 **  Author(s):  Hui Cao <huica@cisco.com>
 **
 **  NOTES
 **  5.25.13 - Initial Source Code. Hui Cao
 **
 **
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_mempool.h"

#include "log/messages.h"
#include "utils/util.h"

#ifdef UNIT_TEST
#include "catch/snort_catch.h"
#endif

using namespace snort;

/*This magic is used for double free detection*/

#define FREE_MAGIC    0x2525252525252525
typedef uint64_t MagicType;


void FileMemPool::free_pools()
{
    if (datapool != nullptr)
    {
        snort_free(datapool);
        datapool = nullptr;
    }

    cbuffer_free(free_list);
    cbuffer_free(released_list);
}

/*
 * Purpose: initialize a FileMemPool object and allocate memory for it
 * Args:
 *   num_objects - number of items in this pool
 *   obj_size    - size of the items
 */

FileMemPool::FileMemPool(uint64_t num_objects, size_t o_size)
{
    unsigned int i;

    if ((num_objects < 1) || (o_size < 1))
        return;

    obj_size = o_size;

    // this is the basis pool that represents all the *data pointers in the list
    datapool = (void**)snort_calloc(num_objects, obj_size);

    /* sets up the memory list */
    free_list = cbuffer_init(num_objects);
    if (!free_list)
    {
        free_pools();
        return;
    }

    released_list = cbuffer_init(num_objects);
    if (!released_list)
    {
        free_pools();
        return;
    }

    total = 0;
    for (i=0; i<num_objects; i++)
    {
        void* data = ((char*)datapool) + (i * obj_size);

        if (cbuffer_write(free_list,  data))
        {
            free_pools();
            return;
        }
        *(MagicType*)data = FREE_MAGIC;
        total++;
    }
}

/*
 * Destroy a set of FileMemPool objects
 *
 */
FileMemPool::~FileMemPool()
{
    free_pools();
}

/*
 * Allocate a new object from the FileMemPool
 *
 * Args:
 *   FileMemPool: pointer to a FileMemPool struct
 *
 * Returns: a pointer to the FileMemPool object on success, nullptr on failure
 */

void* FileMemPool::m_alloc()
{
    void* b = nullptr;

    std::lock_guard<std::mutex> lock(pool_mutex);

    if (cbuffer_read(free_list, &b))
    {
        if (cbuffer_read(released_list, &b))
        {
            return nullptr;
        }
    }

    return b;
}

/*
 * Free a new object from the buffer
 * We use circular buffer to synchronize one reader and one writer
 */
int FileMemPool::remove(CircularBuffer* cb, void* obj)
{
    if (obj == nullptr)
        return FILE_MEM_FAIL;

    // Reject a detected double free BEFORE enqueuing the block. Testing the
    // marker after cbuffer_write() leaves the block queued twice, so a later
    // pair of m_alloc() calls hands the same block to two owners.
    if (*(MagicType*)obj == FREE_MAGIC)
    {
        return FILE_MEM_FAIL;
    }

    if (cbuffer_write(cb, obj))
    {
        return FILE_MEM_FAIL;
    }

    *(MagicType*)obj = FREE_MAGIC;

    return FILE_MEM_SUCCESS;
}

int FileMemPool::m_free(void* obj)
{
    std::lock_guard<std::mutex> lock(pool_mutex);

    int ret = remove(free_list, obj);


    return ret;
}

/*
 * Release a new object from the FileMemPool
 * This can be called by a different thread calling
 * file_mempool_alloc()
 *  *
 */

int FileMemPool::m_release(void* obj)
{
    std::lock_guard<std::mutex> lock(pool_mutex);

    /*A writer that might from different thread*/
    int ret = remove(released_list, obj);


    return ret;
}

/* Returns number of elements allocated in current buffer*/
uint64_t FileMemPool::allocated()
{
    uint64_t total_freed = released() + freed();
    return (total - total_freed);
}

/* Returns number of elements freed in current buffer*/
uint64_t FileMemPool::freed()
{
    return (cbuffer_used(free_list));
}

/* Returns number of elements released in current buffer*/
uint64_t FileMemPool::released()
{
    return (cbuffer_used(released_list));
}

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

#ifdef UNIT_TEST
static inline void mark_block_in_use(void* p)
{
    // In production, callers initialize block headers immediately after m_alloc().
    // Mirror that here so the first free/release is treated as a legitimate return.
    *(MagicType*)p = 0;
}

TEST_CASE("FileMemPool m_free detects double free", "[file_mempool]")
{
    FileMemPool pool(2, sizeof(uint64_t));

    void* ptr = pool.m_alloc();
    REQUIRE(ptr != nullptr);
    mark_block_in_use(ptr);

    CHECK(pool.m_free(ptr) == FILE_MEM_SUCCESS);
    CHECK(pool.m_free(ptr) == FILE_MEM_FAIL);
}

TEST_CASE("FileMemPool m_free double free does not duplicate queue entries", "[file_mempool]")
{
    FileMemPool pool(3, sizeof(uint64_t));

    void* a = pool.m_alloc();
    void* b = pool.m_alloc();
    const void* c = pool.m_alloc();

    REQUIRE(a != nullptr);
    REQUIRE(b != nullptr);
    REQUIRE(c != nullptr);
    REQUIRE(a != b);
    REQUIRE(a != c);
    REQUIRE(b != c);

    mark_block_in_use(a);
    mark_block_in_use(b);

    CHECK(pool.m_free(a) == FILE_MEM_SUCCESS);
    CHECK(pool.m_free(a) == FILE_MEM_FAIL);
    CHECK(pool.m_free(b) == FILE_MEM_SUCCESS);

    const void* first = pool.m_alloc();
    const void* second = pool.m_alloc();

    REQUIRE(first != nullptr);
    REQUIRE(second != nullptr);
    CHECK(first != second);
}

TEST_CASE("FileMemPool m_release double free does not duplicate queue entries", "[file_mempool]")
{
    FileMemPool pool(3, sizeof(uint64_t));

    void* a = pool.m_alloc();
    void* b = pool.m_alloc();
    const void* c = pool.m_alloc();

    REQUIRE(a != nullptr);
    REQUIRE(b != nullptr);
    REQUIRE(c != nullptr);
    REQUIRE(a != b);
    REQUIRE(a != c);
    REQUIRE(b != c);

    mark_block_in_use(a);
    mark_block_in_use(b);

    CHECK(pool.m_release(a) == FILE_MEM_SUCCESS);
    CHECK(pool.m_release(a) == FILE_MEM_FAIL);
    CHECK(pool.m_release(b) == FILE_MEM_SUCCESS);

    const void* first = pool.m_alloc();
    const void* second = pool.m_alloc();

    REQUIRE(first != nullptr);
    REQUIRE(second != nullptr);
    CHECK(first != second);
}
#endif

