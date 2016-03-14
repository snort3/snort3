//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2007-2013 Sourcefire, Inc.
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

#ifndef SNORT_TYPES_H
#define SNORT_TYPES_H

// defines common types if not already defined

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <stdint.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

typedef uint16_t Port;

/* use these macros (and those in <inttypes.h>)
 * for 64 bit format portability
 */
#define STDu64 "%" PRIu64
#define CSVu64 STDu64 ","
#define FMTu64(fmt) "%" fmt PRIu64

#define STDi64 "%" PRIi64
#define CSVi64 STDi64 ","
#define FMTi64(fmt) "%" fmt PRIi64

#define STDx64 "%" PRIx64
#define CSVx64 STDx64 ","
#define FMTx64(fmt) "%" fmt PRIx64

#ifndef UINT8_MAX
#  define UINT8_MAX 0xff
#endif

#ifndef USHRT_MAX
#  define USHRT_MAX  0xffff
#endif

#ifndef UINT16_MAX
#  define UINT16_MAX 0xffff
#endif

#ifndef UINT32_MAX
#  define UINT32_MAX (4294967295U)
#endif

#ifndef UINT64_MAX
#  if SIZEOF_UNSIGNED_LONG_INT == 8
#    define UINT64_MAX (18446744073709551615UL)
#  else
#    define UINT64_MAX (18446744073709551615ULL)
#  endif
#endif

/* Somewhat arbitrary, but should be enough for this application
 * since files shouldn't be buried too deep.  This provides about
 * 15 levels of 255 character path components */
#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif

/* utilities */

#ifndef SIZE_MAX
#define SIZE_MAX 0xFFFFFFFF  // FIXIT-L use c++ define
#endif

#ifndef INT32_MAX
#define INT32_MAX 0x7FFFFFFF  // FIXIT-L use c++ define
#endif

#define UNUSED(x) (void)(x)

#ifndef SO_PUBLIC
#if defined _WIN32 || defined __CYGWIN__
#  ifdef __GNUC__
#    define SO_PUBLIC __attribute__((dllimport))
#  else
#    define SO_PUBLIC __declspec(dllimport)
#  endif
#  define DLL_LOCAL
#else
#  ifdef HAVE_VISIBILITY
#    define SO_PUBLIC  __attribute__ ((visibility("default")))
#    define SO_PRIVATE __attribute__ ((visibility("hidden")))
#  else
#    define SO_PUBLIC
#    define SO_PRIVATE
#  endif
#endif
#endif

/* specifies that a function does not return
 * used for quieting Visual Studio warnings */
#ifdef _MSC_VER
# if _MSC_VER >= 1400
#  define NORETURN __declspec(noreturn)
# else
#  define NORETURN
# endif
#else
# define NORETURN __attribute__ ((noreturn))
#endif

#if !defined(__GNUC__) || __GNUC__ < 2 || \
    (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#define __attribute__(x)    /* delete __attribute__ if non-gcc or gcc1 */
#endif

#endif

