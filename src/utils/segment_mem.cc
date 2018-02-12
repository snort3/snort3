//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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
// 8/7/2011 - Initial implementation ... Hui Cao <hcao@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "segment_mem.h"

#include <cstring>

/*point to the start of the unused memory*/
static MEM_OFFSET unused_ptr = 0;
static size_t unused_mem = 0;
static void* base_ptr = nullptr;

size_t segment_unusedmem()
{
    return unused_mem;
}

/***************************************************************************
 *  Initialize the segment memory
 * Return values:
 *   1: success
 *   0: fail
 **************************************************************************/
int segment_meminit(uint8_t* buff, size_t mem_cap)
{
    base_ptr = buff;
    unused_ptr = 0;
    unused_mem = mem_cap;
    return 1;
}

/***************************************************************************
 * allocate memory block from segment
 * todo:currently, we only allocate memory continuously. Need to reuse freed
 *      memory in the future.
 * return:
 *    0: fail
 *    other: the offset of the allocated memory block
 **************************************************************************/
MEM_OFFSET segment_snort_alloc(size_t size)
{
    MEM_OFFSET current_ptr = unused_ptr;

    if (unused_mem < size)
        return 0;

    unused_ptr += size;
    unused_mem -= size;

    return current_ptr;
}

/***************************************************************************
 * Free memory block from segment
 * Todo: currently, no action for free. Need to reuse freed memory in the
 *       future.
 **************************************************************************/

void segment_free(MEM_OFFSET)
{
}

/***************************************************************************
 * allocate memory block from segment and initialize it to zero
 * It calls segment_snort_alloc() to get memory.
 * todo:currently, we only allocate memory continuously. Need to reuse freed
 *      memory in the future.
 * return:
 *    0: fail
 *    other: the offset of the allocated memory block
 **************************************************************************/

MEM_OFFSET segment_snort_calloc(size_t num, size_t size)
{
    MEM_OFFSET current_ptr;
    size_t total;

    if ((0 == size)||(0 == num))
        return 0;
    /*Check possible overflow*/
    if (num > SIZE_MAX/size)
        return 0;
    total = num * size;
    current_ptr = segment_snort_alloc(total);
    if (0 != current_ptr)
        memset((uint8_t*)base_ptr + current_ptr, 0, total);

    return current_ptr;
}

void* segment_basePtr()
{
    return base_ptr;
}

