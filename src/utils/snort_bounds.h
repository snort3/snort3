//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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
// snort_bounds.h author Chris Green <cmg@sourcefire.com>

#ifndef SNORT_BOUNDS_H
#define SNORT_BOUNDS_H

#include <assert.h>
#include <string.h>

// Bounds checking for pointers to buffers

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define SAFEMEM_ERROR 0  // FIXIT-L get rid of these
#define SAFEMEM_SUCCESS 1

#ifdef DEBUG
#define ERRORRET assert(0==1)
#else
#define ERRORRET return SAFEMEM_ERROR;
#endif

// Check to make sure that p is less than or equal to the ptr range
// returns 1 if in bounds, 0 otherwise
// FIXIT-L change return type to bool
inline int inBounds(const void* start, const void* end, const void* p)
{
    const uint8_t* pstart = (uint8_t*)start;
    const uint8_t* pend = (uint8_t*)end;
    const uint8_t* pp = (uint8_t*)p;

    return (pp >= pstart) && (pp < pend);
}

// FIXIT-L change return type to bool
inline int SafeMemCheck(const void* dst, size_t n,
    const void* start, const void* end)
{
    const uint8_t* pstart = (uint8_t*)start;
    const uint8_t* pend = (uint8_t*)end;
    const uint8_t* pdst = (uint8_t*)dst;

    const uint8_t* tmp;

    if (n < 1)
        return SAFEMEM_ERROR;

    if ((pdst == NULL) || (pstart == NULL) || (pend == NULL))
        return SAFEMEM_ERROR;

    tmp = pdst + (n - 1);

    if (!inBounds(pstart, pend, pdst) || !inBounds(pstart, pend, tmp))
        return SAFEMEM_ERROR;

    return SAFEMEM_SUCCESS;
}

// returns SAFEMEM_ERROR on failure, SAFEMEM_SUCCESS on success
// FIXIT-L change return type to bool
// FIXIT-M remove code in extras that requires this. Do not use for new code.
inline int SafeMemcpy(
    void* dst, const void* src, size_t n, const void* start, const void* end)
{
    if ( !n )
        return SAFEMEM_SUCCESS;
    if (SafeMemCheck(dst, n, start, end) != SAFEMEM_SUCCESS)
        ERRORRET;
    if (src == NULL)
        ERRORRET;
    memcpy(dst, src, n);
    return SAFEMEM_SUCCESS;
}

#endif

