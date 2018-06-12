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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "util_cstring.h"

#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace snort
{
/* Guaranteed to be '\0' terminated even if truncation occurs.
 *
 * returns  SNORT_SNPRINTF_SUCCESS if successful
 * returns  SNORT_SNPRINTF_TRUNCATION on truncation
 * returns  SNORT_SNPRINTF_ERROR on error
 */
int SnortSnprintf(char* buf, size_t buf_size, const char* format, ...)
{
    va_list ap;
    int ret;

    if (buf == nullptr || buf_size == 0 || format == nullptr)
        return SNORT_SNPRINTF_ERROR;

    /* zero first byte in case an error occurs with
     * vsnprintf, so buffer is null terminated with
     * zero length */
    buf[0] = '\0';
    buf[buf_size - 1] = '\0';

    va_start(ap, format);

    ret = vsnprintf(buf, buf_size, format, ap);

    va_end(ap);

    if (ret < 0)
        return SNORT_SNPRINTF_ERROR;

    if (buf[buf_size - 1] != '\0' || (size_t)ret >= buf_size)
    {
        /* result was truncated */
        buf[buf_size - 1] = '\0';
        return SNORT_SNPRINTF_TRUNCATION;
    }

    return SNORT_SNPRINTF_SUCCESS;
}

/* Appends to a given string
 * Guaranteed to be '\0' terminated even if truncation occurs.
 *
 * returns SNORT_SNPRINTF_SUCCESS if successful
 * returns SNORT_SNPRINTF_TRUNCATION on truncation
 * returns SNORT_SNPRINTF_ERROR on error
 */
int SnortSnprintfAppend(char* buf, size_t buf_size, const char* format, ...)
{
    int str_len;
    int ret;
    va_list ap;

    if (buf == nullptr || buf_size == 0 || format == nullptr)
        return SNORT_SNPRINTF_ERROR;

    str_len = SnortStrnlen(buf, buf_size);

    /* since we've already checked buf and buf_size an error
     * indicates no null termination, so just start at
     * beginning of buffer */
    if (str_len == SNORT_STRNLEN_ERROR)
    {
        buf[0] = '\0';
        str_len = 0;
    }

    buf[buf_size - 1] = '\0';

    va_start(ap, format);

    ret = vsnprintf(buf + str_len, buf_size - (size_t)str_len, format, ap);

    va_end(ap);

    if (ret < 0)
        return SNORT_SNPRINTF_ERROR;

    if (buf[buf_size - 1] != '\0' || (size_t)ret >= buf_size)
    {
        /* truncation occurred */
        buf[buf_size - 1] = '\0';
        return SNORT_SNPRINTF_TRUNCATION;
    }

    return SNORT_SNPRINTF_SUCCESS;
}

/* Guaranteed to be '\0' terminated even if truncation occurs.
 *
 * Arguments:  dst - the string to contain the copy
 *             src - the string to copy from
 *             dst_size - the size of the destination buffer
 *                        including the null byte.
 *
 * returns SNORT_STRNCPY_SUCCESS if successful
 * returns SNORT_STRNCPY_TRUNCATION on truncation
 * returns SNORT_STRNCPY_ERROR on error
 *
 * Note: Do not set dst[0] = '\0' on error since it's possible that
 * dst and src are the same pointer - it will at least be null
 * terminated in any case
 */
int SnortStrncpy(char* dst, const char* src, size_t dst_size)
{
    char* ret = nullptr;

    if (dst == nullptr || src == nullptr || dst_size == 0)
        return SNORT_STRNCPY_ERROR;

    dst[dst_size - 1] = '\0';

    ret = strncpy(dst, src, dst_size);

    /* Not sure if this ever happens but might as
     * well be on the safe side */
    if (ret == nullptr)
        return SNORT_STRNCPY_ERROR;

    if (dst[dst_size - 1] != '\0')
    {
        /* result was truncated */
        dst[dst_size - 1] = '\0';
        return SNORT_STRNCPY_TRUNCATION;
    }

    return SNORT_STRNCPY_SUCCESS;
}

/* Determines whether a buffer is '\0' terminated and returns the
 * string length if so
 *
 * returns the string length if '\0' terminated
 * returns SNORT_STRNLEN_ERROR if not '\0' terminated
 */
int SnortStrnlen(const char* buf, int buf_size)
{
    int i = 0;

    if (buf == nullptr || buf_size <= 0)
        return SNORT_STRNLEN_ERROR;

    for (i = 0; i < buf_size; i++)
    {
        if (buf[i] == '\0')
            break;
    }

    if (i == buf_size)
        return SNORT_STRNLEN_ERROR;

    return i;
}

/*
 * Find first occurrence of char of accept in s, limited by slen.
 * A 'safe' version of strpbrk that won't read past end of buffer s
 * in cases that s is not NULL terminated.
 *
 * This code assumes 'accept' is a static string.
 */
const char* SnortStrnPbrk(const char* s, int slen, const char* accept)
{
    if (!s || (slen == 0) || !*s || !accept)
        return nullptr;

    const char* s_end = s + slen;

    while (s < s_end)
    {
        char ch = *s;

        if (strchr(accept, ch))
            return s;
        s++;
    }
    return nullptr;
}

/*
 * Find first occurrence of searchstr in s, limited by slen.
 * A 'safe' version of strstr that won't read past end of buffer s
 * in cases that s is not NULL terminated.
 */
const char* SnortStrnStr(const char* s, int slen, const char* searchstr)
{
    if (!s || (slen == 0) || !*s || !searchstr)
        return nullptr;

    char ch;

    if ((ch = *searchstr++) != 0)
    {
        int len = strlen(searchstr);
        do
        {
            char nc;
            do
            {
                if ((nc = *s++) == 0)
                {
                    return nullptr;
                }
                slen--;
                if (slen == 0)
                    return nullptr;
            }
            while (nc != ch);

            if (slen - len < 0)
                return nullptr;
        }
        while (memcmp(s, searchstr, len) != 0);
        s--;
    }
    return s;
}

/*
 * Find first occurrence of substring in s, ignore case.
*/
const char* SnortStrcasestr(const char* s, int slen, const char* substr)
{
    if (!s || (slen == 0) || !*s || !substr)
        return nullptr;

    char ch;

    if ((ch = *substr++) != 0)
    {
        ch = tolower((char)ch);
        int len = strlen(substr);

        do
        {
            char nc;
            do
            {
                if ((nc = *s++) == 0)
                {
                    return nullptr;
                }
                slen--;
                if (slen == 0)
                    return nullptr;
            }
            while ((char)tolower((uint8_t)nc) != ch);

            if (slen - len < 0)
                return nullptr;
        }
        while (strncasecmp(s, substr, len) != 0);
        s--;
    }
    return s;
}

/****************************************************************************
 *
 * Function: sfsnprintfappend
 *
 * Purpose: snprintf that appends to destination buffer
 *
 *          Appends the snprintf format string and arguments to dest
 *          without going beyond dsize bounds.  Assumes dest has
 *          been properly allocated, and is of dsize in length.
 *
 * Arguments: dest      ==> pointer to string buffer to append to
 *            dsize     ==> size of buffer dest
 *            format    ==> snprintf format string
 *            ...       ==> arguments for printf
 *
 * Returns: number of characters added to the buffer
 *
 ****************************************************************************/
int sfsnprintfappend(char* dest, int dsize, const char* format, ...)
{
    int currLen, appendLen;
    va_list ap;

    if (!dest || dsize == 0)
        return -1;

    currLen = SnortStrnlen(dest, dsize);
    if (currLen == -1)
        return -1;

    va_start(ap, format);
    appendLen = vsnprintf(dest+currLen, dsize-currLen, format, ap);
    va_end(ap);

    dest[dsize-1]=0; /* guarantee a null termination */

    if (appendLen >= (dsize - currLen))
        appendLen = dsize - currLen - 1;
    else if (appendLen < 0)
        appendLen = 0;

    return appendLen;
}

// return actual number of bytes written to buffer s
int safe_snprintf(char* s, size_t n, const char* format, ... )
{
    va_list ap;

    va_start(ap, format);
    int len = vsnprintf(s, n, format, ap);
    va_end(ap);

    if (len >= (int)n)
        len = n - 1;
    else if (len < 0)
        len = 0;

    return len;
}

}

