//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2006-2013 Sourcefire, Inc.
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

#ifndef CPUCLOCK_H
#define CPUCLOCK_H

// Assembly to find clock ticks
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>

// INTEL LINUX/BSD/..
#if (defined(__i386) || defined(__amd64) || defined(__x86_64__))
#define get_clockticks(val) \
{ \
    uint32_t a, d; \
    __asm__ __volatile__ ("rdtsc" : "=a" (a), "=d" (d));  \
    val = ((uint64_t)a) | (((uint64_t)d) << 32);  \
}
#else
#if (defined(__ia64) && defined(__GNUC__) )
#define get_clockticks(val) \
{ \
    __asm__ __volatile__ ("mov %0=ar.itc" : "=r" (val)); \
}
#else
#if (defined(__ia64) && defined(__hpux))
#include <machine/sys/inline.h>
#define get_clockticks(val) \
{ \
    val = _Asm_mov_from_ar (_AREG_ITC); \
}
#else
// POWER PC
#if (defined(__GNUC__) && (defined(__powerpc__) || (defined(__ppc__))))
#define get_clockticks(val) \
{ \
    uint32_t tbu0, tbu1, tbl; \
    do \
    { \
        __asm__ __volatile__ ("mftbu %0" : "=r" (tbu0)); \
        __asm__ __volatile__ ("mftb  %0" : "=r" (tbl)); \
        __asm__ __volatile__ ("mftbu %0" : "=r" (tbu1)); \
    } while (tbu0 != tbu1); \
    val = ((uint64_t)tbl) | (((uint64_t)tbu0) << 32);  \
}
#else
// SPARC
#ifdef SPARCV9
#ifdef _LP64
#define get_clockticks(val) \
{ \
    __asm__ __volatile__ ("rd %%tick, %0" : "=r" (val)); \
}
#else
#define get_clockticks(val) \
{ \
    uint32_t a, b; \
    __asm__ __volatile__ ("rd %%tick, %0\n" \
        "srlx %0, 32, %1" \
        : "=r" (a), "=r" (b)); \
    val = ((uint64_t)a) | (((uint64_t)b) << 32); \
}
#endif // _LP64
#else
#define get_clockticks(val)
#endif // SPARCV9
#endif // __GNUC__ && __powerpc__ || __ppc__
#endif // __ia64 && __hpux
#endif // __ia64 && __GNUC__
#endif // __i386 || __amd64 || __x86_64__

inline double get_ticks_per_usec()
{
    uint64_t start = 0, end = 0;
    get_clockticks(start);

    sleep(1);
    get_clockticks(end);

    return (double)(end-start)/1e6;
}

#endif

