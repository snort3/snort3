//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// Bounds checking for pointers to buffers

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdarg.h>
#ifdef DEBUG
#include <assert.h>
#endif
#include <unistd.h>

// FIXIT-L: Change dependent return types to bool and git rid of these
#define SAFEMEM_ERROR 0
#define SAFEMEM_SUCCESS 1

#ifdef DEBUG
#define ERRORRET assert(0==1)
#else
#define ERRORRET return SAFEMEM_ERROR;
#endif

#define MAXPORTS 65536
#define MAXPORTS_STORAGE 8192

// Check to make sure that p is less than or equal to the ptr range
// returns 1 if in bounds, 0 otherwise
// FIXIT-L: Change return type to bool
static inline int inBounds(const void* start, const void* end, const void* p)
{
    const uint8_t* pstart = (uint8_t*)start;
    const uint8_t* pend = (uint8_t*)end;
    const uint8_t* pp = (uint8_t*)p;

    if ((pp >= pstart) && (pp < pend))
        return 1;
    return 0;
}

// FIXIT-L: Change return type to bool
static inline int SafeMemCheck(const void* dst, size_t n,
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
// FIXIT-L: Change return type to bool
static inline int SafeMemcpy(
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

// dst and src can be in the same buffer
// returns SAFEMEM_ERROR on failure, SAFEMEM_SUCCESS on success
// FIXIT-L: Change return type to bool
static inline int SafeMemmove(
    void* dst, const void* src, size_t n, const void* start, const void* end)
{
    if (SafeMemCheck(dst, n, start, end) != SAFEMEM_SUCCESS)
        ERRORRET;
    if (src == NULL)
        ERRORRET;
    memmove(dst, src, n);
    return SAFEMEM_SUCCESS;
}

// dst and src can be in the same buffer
// returns SAFEMEM_ERROR on failure, SAFEMEM_SUCCESS on success
// FIXIT-L: Change return type to bool
static inline int SafeBoundsMemmove(
    void* dst, const void* src, size_t n, const void* start, const void* end)
{
    size_t overlap = 0;
    if (SafeMemCheck(dst, n, start, end) != SAFEMEM_SUCCESS)
        ERRORRET;
    if (src == NULL)
        ERRORRET;

    if ( src == dst )
    {
        return SAFEMEM_SUCCESS;
    }
    else if (inBounds(dst, ((uint8_t*)dst + n), src))
    {
        overlap = (uint8_t*)src - (uint8_t*)dst;
        memcpy(dst, src, overlap);
        memmove(((uint8_t*)dst + overlap), ((uint8_t*)src + overlap), (n - overlap));
    }
    else if (inBounds(src, ((uint8_t*)src + n), dst))
    {
        overlap = (uint8_t*)dst - (uint8_t*)src;
        memcpy(((uint8_t*)dst + overlap), ((uint8_t*)src + overlap), (n - overlap));
        memmove(dst, src, overlap);
    }
    else
    {
        memcpy(dst, src, n);
    }
    return SAFEMEM_SUCCESS;
}

// returns SAFEMEM_ERROR on failure, SAFEMEM_SUCCESS on success
// FIXIT-L: Change return type to bool
static inline int SafeMemset(
    void* dst, uint8_t c, size_t n, const void* start, const void* end)
{
    if (SafeMemCheck(dst, n, start, end) != SAFEMEM_SUCCESS)
        ERRORRET;
    memset(dst, c, n);
    return SAFEMEM_SUCCESS;
}

// returns 0 on failure, 1 on success
// FIXIT-L: Change return type to bool
static inline int SafeWrite(uint8_t* start, uint8_t* end, uint8_t* dst, uint8_t* src)
{
    if (!inBounds(start, end, dst))
    {
        ERRORRET;
    }

    *dst = *src;
    return 1;
}

// returns 0 on failure, 1 on success
// FIXIT-L: Change return type to bool
static inline int SafeRead(uint8_t* start, uint8_t* end, uint8_t* src, uint8_t* read)
{
    if (!inBounds(start,end, src))
    {
        ERRORRET;
    }

    *read = *start;
    return 1;
}

// An wrapper around snprintf to make it safe.
// returns the number of bytes written to the buffer
static inline size_t SafeSnprintf(char* str, size_t size, const char* format, ...)
{
    va_list ap;
    int ret;

    if (size == 0)
        return 0;

    va_start(ap, format);
    ret = vsnprintf(str, size, format, ap);
    va_end(ap);

    if (ret < 0 || (size_t)ret > size)
        return 0;

    return (size_t)ret;
}

#endif

