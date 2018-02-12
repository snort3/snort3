//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef UTIL_CSTRING_H
#define UTIL_CSTRING_H

// Utility functions and macros for interacting with and parsing C strings

#include <cctype>
#include <cerrno>
#include <cstdlib>

#include "main/snort_types.h"

#define SNORT_SNPRINTF_SUCCESS 0
#define SNORT_SNPRINTF_TRUNCATION 1
#define SNORT_SNPRINTF_ERROR (-1)

#define SNORT_STRNCPY_SUCCESS 0
#define SNORT_STRNCPY_TRUNCATION 1
#define SNORT_STRNCPY_ERROR (-1)
#define SNORT_STRNLEN_ERROR (-1)

SO_PUBLIC int safe_snprintf(char*, size_t, const char*, ... )
    __attribute__((format (printf, 3, 4)));
// these functions are deprecated; use C++ strings instead
SO_PUBLIC int SnortSnprintf(char*, size_t, const char*, ...)
    __attribute__((format (printf, 3, 4)));
SO_PUBLIC int SnortSnprintfAppend(char*, size_t, const char*, ...)
    __attribute__((format (printf, 3, 4)));

SO_PUBLIC const char* SnortStrcasestr(const char* s, int slen, const char* substr);
SO_PUBLIC const char* SnortStrnStr(const char* s, int slen, const char* searchstr);
SO_PUBLIC const char* SnortStrnPbrk(const char* s, int slen, const char* accept);

SO_PUBLIC int SnortStrncpy(char*, const char*, size_t);
SO_PUBLIC int SnortStrnlen(const char*, int);

SO_PUBLIC int sfsnprintfappend(char* dest, int dsize, const char* format, ...)
    __attribute__((format (printf, 3, 4)));

inline long SnortStrtol(const char* nptr, char** endptr, int base)
{
    long iRet;
    errno = 0;
    iRet = strtol(nptr, endptr, base);

    return iRet;
}

inline unsigned long SnortStrtoul(const char* nptr, char** endptr, int base)
{
    unsigned long iRet;
    errno = 0;
    iRet = strtoul(nptr, endptr, base);

    return iRet;
}

// Checks to make sure we're not going to evaluate a negative number for which
// strtoul() gladly accepts and parses returning an underflowed wrapped unsigned
// long without error.
// Buffer passed in MUST be '\0' terminated.
//
// Returns
//  int
//    -1 if buffer is nothing but spaces or first non-space character is a
//       negative sign.  Also if errno is EINVAL (which may be due to a bad
//       base) or there was nothing to convert.
//     0 on success
//
// Populates pointer to uint32_t value passed in which should
// only be used on a successful return from this function.
//
// Also will set errno to ERANGE on a value returned from strtoul that is
// greater than UINT32_MAX, but still return success.
//
inline int SnortStrToU32(const char* buffer, char** endptr,
    uint32_t* value, int base)
{
    unsigned long int tmp;

    if ((buffer == nullptr) || (endptr == nullptr) || (value == nullptr))
        return -1;

    // Only positive numbers should be processed and strtoul will
    // eat up white space and process '-' and '+' so move past
    // white space and check for a negative sign.
    while (isspace((int)*buffer))
        buffer++;

    // If all spaces or a negative sign is found, return error.
    // XXX May also want to exclude '+' as well.
    if ((*buffer == '\0') || (*buffer == '-'))
        return -1;

    tmp = SnortStrtoul(buffer, endptr, base);

    // The user of the function should check for ERANGE in errno since this
    // function can be used such that an ERANGE error is acceptable and
    // value gets truncated to UINT32_MAX.
    if ((errno == EINVAL) || (*endptr == buffer))
        return -1;

    // If value is greater than a UINT32_MAX set value to UINT32_MAX
    // and errno to ERANGE
    if (tmp > UINT32_MAX)
    {
        tmp = UINT32_MAX;
        errno = ERANGE;
    }

    *value = (uint32_t)tmp;

    return 0;
}

#endif

