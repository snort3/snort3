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
 **  Author(s):  Hui Cao <huica@cisco.com>
 **
 **  NOTES
 **  5.25.13 - Initial Source Code. Hui Cao
 **
 **
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "file_mempool.h"
#include "main/snort_debug.h"
#include "utils/util.h"

/*This magic is used for double free detection*/

#define FREE_MAGIC    0x2525252525252525
typedef uint64_t MagicType;

#ifdef DEBUG_MSGS
static inline void file_mempool_verify(FileMemPool* mempool)
{
    uint64_t free_size;
    uint64_t release_size;

    free_size = cbuffer_used(mempool->free_list);
    release_size = cbuffer_used(mempool->released_list);

    if (free_size > cbuffer_size(mempool->free_list))
    {
        ErrorMessage("%s(%d) file_mempool: failed to verify free list!\n",
            __FILE__, __LINE__);
    }

    if (release_size > cbuffer_size(mempool->released_list))
    {
        ErrorMessage("%s(%d) file_mempool: failed to verify release list!\n",
            __FILE__, __LINE__);
    }

    /* The free mempool and size of release mempool should be smaller than
     * or equal to the size of mempool
     */
    if (free_size + release_size > mempool->total)
    {
        ErrorMessage("%s(%d) file_mempool: failed to verify mempool size!\n",
            __FILE__, __LINE__);
    }
}
#endif

static inline void file_mempool_free_pools(FileMemPool* mempool)
{
    if (mempool == NULL)
        return;

    if (mempool->datapool != NULL)
    {
        snort_free(mempool->datapool);
        mempool->datapool = NULL;
    }

    cbuffer_free(mempool->free_list);
    cbuffer_free(mempool->released_list);
}

/* Function: int file_mempool_init(FileMemPool *FileMemPool,
 *                            PoolCount num_objects, size_t obj_size)
 *
 * Purpose: initialize a FileMemPool object and allocate memory for it
 * Args:
 *   FileMemPool - pointer to a FileMemPool struct
 *   num_objects - number of items in this pool
 *   obj_size    - size of the items
 *
 * Returns:
 *   FILE_MEM_SUCCESS
 *   FILE_MEM_FAIL
 */

int file_mempool_init(FileMemPool* mempool, uint64_t num_objects, size_t obj_size)
{
    unsigned int i;

    if ((mempool == NULL) || (num_objects < 1) || (obj_size < 1))
        return FILE_MEM_FAIL;

    mempool->obj_size = obj_size;

    // this is the basis pool that represents all the *data pointers in the list
    mempool->datapool = (void**)snort_calloc(num_objects, obj_size);

    /* sets up the memory list */
    mempool->free_list = cbuffer_init(num_objects);
    if (!mempool->free_list)
    {
        ErrorMessage("%s(%d) file_mempool_init(): Failed to init free list\n",
            __FILE__, __LINE__);
        file_mempool_free_pools(mempool);
        return FILE_MEM_FAIL;
    }

    mempool->released_list = cbuffer_init(num_objects);
    if (!mempool->released_list)
    {
        ErrorMessage("%s(%d) file_mempool_init(): "
            "Failed to init release list\n", __FILE__, __LINE__);
        file_mempool_free_pools(mempool);
        return FILE_MEM_FAIL;
    }

    for (i=0; i<num_objects; i++)
    {
        void* data = ((char*)mempool->datapool) + (i * mempool->obj_size);

        if (cbuffer_write(mempool->free_list,  data))
        {
            ErrorMessage("%s(%d) file_mempool_init(): "
                "Failed to add to free list\n",
                __FILE__, __LINE__);
            file_mempool_free_pools(mempool);
            return FILE_MEM_FAIL;
        }
        *(MagicType*)data = FREE_MAGIC;
        mempool->total++;
    }

    return FILE_MEM_SUCCESS;
}

/*
 * Destroy a set of FileMemPool objects
 *
 * Args:
 *   FileMemPool: pointer to a FileMemPool struct
 *
 * Return:
 *   FILE_MEM_SUCCESS
 *   FILE_MEM_FAIL
 */
int file_mempool_destroy(FileMemPool* mempool)
{
    if (mempool == NULL)
        return FILE_MEM_FAIL;

    file_mempool_free_pools(mempool);

    return FILE_MEM_SUCCESS;
}

/*
 * Allocate a new object from the FileMemPool
 *
 * Args:
 *   FileMemPool: pointer to a FileMemPool struct
 *
 * Returns: a pointer to the FileMemPool object on success, NULL on failure
 */

void* file_mempool_alloc(FileMemPool* mempool)
{
    void* b = NULL;

    if (mempool == NULL)
    {
        return NULL;
    }

    if (cbuffer_read(mempool->free_list, &b))
    {
        if (cbuffer_read(mempool->released_list, &b))
        {
            return NULL;
        }
    }

    if (*(MagicType*)b != FREE_MAGIC)
    {
        ErrorMessage("%s(%d) file_mempool_alloc(): Allocation errors! \n",
            __FILE__, __LINE__);
    }

    DEBUG_WRAP(file_mempool_verify(mempool); );

    return b;
}

/*
 * Free a new object from the buffer
 * We use circular buffer to synchronize one reader and one writer
 *
 * Args:
 *   FileMemPool: pointer to a circular buffer struct
 *   void *obj  : memory object
 *
 * Return:
 *   FILE_MEM_SUCCESS
 *   FILE_MEM_FAIL
 */
static inline int _file__mempool_remove(CircularBuffer* cb, void* obj)
{
    if (obj == NULL)
        return FILE_MEM_FAIL;

    if (cbuffer_write(cb, obj))
    {
        return FILE_MEM_FAIL;
    }

    if (*(MagicType*)obj == FREE_MAGIC)
    {
        DEBUG_WRAP(ErrorMessage("%s(%d) file_mempool_remove(): Double free! \n",
                __FILE__, __LINE__); );
        return FILE_MEM_FAIL;
    }

    *(MagicType*)obj = FREE_MAGIC;

    return FILE_MEM_SUCCESS;
}

/*
 * Free a new object from the FileMemPool
 *
 * Args:
 *   FileMemPool: pointer to a FileMemPool struct
 *   void *obj  : memory object
 *
 * Return:
 *   FILE_MEM_SUCCESS
 *   FILE_MEM_FAIL
 */

int file_mempool_free(FileMemPool* mempool, void* obj)
{
    int ret;

    assert(mempool);

    ret = _file__mempool_remove(mempool->free_list, obj);

    DEBUG_WRAP(file_mempool_verify(mempool); );

    return ret;
}

/*
 * Release a new object from the FileMemPool
 * This can be called by a different thread calling
 * file_mempool_alloc()
 *  *
 * Args:
 *   FileMemPool: pointer to a FileMemPool struct
 *   void *obj  : memory object
 *
 * Return:
 *   FILE_MEM_SUCCESS
 *   FILE_MEM_FAIL
 */

int file_mempool_release(FileMemPool* mempool, void* obj)
{
    int ret;

    if (mempool == NULL)
        return FILE_MEM_FAIL;

    /*A writer that might from different thread*/
    ret = _file__mempool_remove(mempool->released_list, obj);

    DEBUG_WRAP(file_mempool_verify(mempool); );

    return ret;
}

/* Returns number of elements allocated in current buffer*/
uint64_t file_mempool_allocated(FileMemPool* mempool)
{
    uint64_t total_freed =
        file_mempool_released(mempool) + file_mempool_freed(mempool);
    return (mempool->total - total_freed);
}

/* Returns number of elements freed in current buffer*/
uint64_t file_mempool_freed(FileMemPool* mempool)
{
    return (cbuffer_used(mempool->free_list));
}

/* Returns number of elements released in current buffer*/
uint64_t file_mempool_released(FileMemPool* mempool)
{
    return (cbuffer_used(mempool->released_list));
}

