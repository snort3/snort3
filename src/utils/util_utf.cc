//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2010-2013 Sourcefire, Inc.
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

/* Some UTF-{16,32}{le,be} normalization functions */

#include "util_utf.h"

#include <stdlib.h>

#define DSTATE_FIRST 0
#define DSTATE_SECOND 1
#define DSTATE_THIRD 2
#define DSTATE_FOURTH 3

/* init a new decode_utf_state_t */
int init_decode_utf_state(decode_utf_state_t* p)
{
    if (p == NULL)
        return DECODE_UTF_FAILURE;

    p->state = DSTATE_FIRST;
    p->charset = CHARSET_DEFAULT;
    return DECODE_UTF_SUCCESS;
}

/* terminate a decode_utf_state_t.
   returns DECODE_UTF_FAILURE if we're not at the base state. */
int term_decode_utf_state(decode_utf_state_t* dead)
{
    if (dead == NULL)
        return DECODE_UTF_FAILURE;

    if (dead->state != DSTATE_FIRST)
        return DECODE_UTF_FAILURE;

    return DECODE_UTF_SUCCESS;
}

/* setters & getters */
int set_decode_utf_state_charset(decode_utf_state_t* dstate, int charset)
{
    if (dstate == NULL)
        return DECODE_UTF_FAILURE;

    dstate->state = DSTATE_FIRST;
    dstate->charset = charset;
    return DECODE_UTF_SUCCESS;
}

int get_decode_utf_state_charset(decode_utf_state_t* dstate)
{
    if (dstate == NULL)
        return DECODE_UTF_FAILURE;

    return dstate->charset;
}

/* Decode UTF-16le from src to dst.
 *
 * src          => buffer containing utf-16le text
 * src_len      => length of src
 * dst          => buffer to write translated text
 * dst_len      => length allocated for dst
 * bytes_copied => store the # of bytes copied to dst
 * dstate       => saved state from last call
 *
 * returns: DECODE_UTF_SUCCESS or DECODE_UTF_FAILURE
 */

static int DecodeUTF16LE(char* src, unsigned int src_len, char* dst, unsigned int dst_len,
    int* bytes_copied, decode_utf_state_t* dstate)
{
    char* src_index = src;
    char* dst_index = dst;
    int result = DECODE_UTF_SUCCESS;

    if (src == NULL || dst == NULL || bytes_copied == NULL || dstate == NULL || src_len == 0 ||
        dst_len == 0)
        return DECODE_UTF_FAILURE;

    while ((src_index < (char*)(src + src_len)) &&
        (dst_index < (char*)(dst + dst_len)))
    {
        /* Copy first byte, skip second, failing if second byte != 0 */
        switch (dstate->state)
        {
        case DSTATE_FIRST:
            *dst_index++ = *src_index++;
            dstate->state = DSTATE_SECOND;
            break;
        case DSTATE_SECOND:
            if (*src_index++ > 0)
                result = DECODE_UTF_FAILURE;
            dstate->state = DSTATE_FIRST;
            break;
        default:
            return DECODE_UTF_FAILURE;
        }
    }

    *bytes_copied = (int)(dst_index - dst);

    return result;
}

/* Decode UTF-16be from src to dst.
 *
 * src          => buffer containing utf-16le text
 * src_len      => length of src
 * dst          => buffer to write translated text
 * dst_len      => length allocated for dst
 * bytes_copied => store the # of bytes copied to dst
 * dstate       => saved state from last call
 *
 * returns: DECODE_UTF_SUCCESS or DECODE_UTF_FAILURE
 */

static int DecodeUTF16BE(char* src, unsigned int src_len, char* dst, unsigned int dst_len,
    int* bytes_copied, decode_utf_state_t* dstate)
{
    char* src_index = src;
    char* dst_index = dst;
    int result = DECODE_UTF_SUCCESS;

    if (src == NULL || dst == NULL || bytes_copied == NULL || dstate == NULL || src_len == 0 ||
        dst_len == 0)
        return DECODE_UTF_FAILURE;

    while ((src_index < (char*)(src + src_len)) &&
        (dst_index < (char*)(dst + dst_len)))
    {
        /* Skip first byte, copy second. */
        switch (dstate->state)
        {
        case DSTATE_FIRST:
            if (*src_index++ > 0)
                result = DECODE_UTF_FAILURE;
            dstate->state = DSTATE_SECOND;
            break;
        case DSTATE_SECOND:
            *dst_index++ = *src_index++;
            dstate->state = DSTATE_FIRST;
            break;
        default:
            return DECODE_UTF_FAILURE;
        }
    }

    *bytes_copied = (int)(dst_index - dst);

    return result;
}

/* Decode UTF-32le from src to dst.
 *
 * src          => buffer containing utf-16le text
 * src_len      => length of src
 * dst          => buffer to write translated text
 * dst_len      => length allocated for dst
 * bytes_copied => store the # of bytes copied to dst
 * dstate       => saved state from last call
 *
 * returns: DECODE_UTF_SUCCESS or DECODE_UTF_FAILURE
 */

static int DecodeUTF32LE(char* src, unsigned int src_len, char* dst, unsigned int dst_len,
    int* bytes_copied, decode_utf_state_t* dstate)
{
    char* src_index = src;
    char* dst_index = dst;
    int result = DECODE_UTF_SUCCESS;

    if (src == NULL || dst == NULL || bytes_copied == NULL || dstate == NULL || src_len == 0 ||
        dst_len == 0)
        return DECODE_UTF_FAILURE;

    while ((src_index < (char*)(src + src_len)) &&
        (dst_index < (char*)(dst + dst_len)))
    {
        /* Copy the first byte, then skip three. */
        switch (dstate->state)
        {
        case DSTATE_FIRST:
            *dst_index++ = *src_index++;
            dstate->state++;
            break;
        case DSTATE_SECOND:
        case DSTATE_THIRD:
        case DSTATE_FOURTH:
            if (*src_index++ > 0)
                result = DECODE_UTF_FAILURE;
            if (dstate->state == DSTATE_FOURTH)
                dstate->state = DSTATE_FIRST;
            else
                dstate->state++;
            break;
        default:
            return DECODE_UTF_FAILURE;
        }
    }

    *bytes_copied = (int)(dst_index - dst);

    return result;
}

/* Decode UTF-32be from src to dst.
 *
 * src          => buffer containing utf-16le text
 * src_len      => length of src
 * dst          => buffer to write translated text
 * dst_len      => length allocated for dst
 * bytes_copied => store the # of bytes copied to dst
 * dstate       => saved state from last call
 *
 * returns: DECODE_UTF_SUCCESS or DECODE_UTF_FAILURE
 */

static int DecodeUTF32BE(char* src, unsigned int src_len, char* dst, unsigned int dst_len,
    int* bytes_copied, decode_utf_state_t* dstate)
{
    char* src_index = src;
    char* dst_index = dst;
    int result = DECODE_UTF_SUCCESS;

    if (src == NULL || dst == NULL || bytes_copied == NULL || dstate == NULL || src_len == 0 ||
        dst_len == 0)
        return DECODE_UTF_FAILURE;

    while ((src_index < (char*)(src + src_len)) &&
        (dst_index < (char*)(dst + dst_len)))
    {
        /* Skip 3 bytes, copy the fourth. */
        switch (dstate->state)
        {
        case DSTATE_FIRST:
        case DSTATE_SECOND:
        case DSTATE_THIRD:
            if (*src_index++ > 0)
                result = DECODE_UTF_FAILURE;
            dstate->state++;
            break;
        case DSTATE_FOURTH:
            *dst_index++ = *src_index++;
            dstate->state = DSTATE_FIRST;
            break;
        default:
            return DECODE_UTF_FAILURE;
        }
    }

    *bytes_copied = (int)(dst_index - dst);

    return result;
}

/* Wrapper function for DecodeUTF{16,32}{LE,BE} */
int DecodeUTF(
    char* src, unsigned int src_len, char* dst, unsigned int dst_len,
    int* bytes_copied, decode_utf_state_t* dstate)
{
    if ( !src || !dst || !bytes_copied || !dstate || !src_len || !dst_len )
        return DECODE_UTF_FAILURE;

    switch (dstate->charset)
    {
    case CHARSET_UTF16LE:
        return DecodeUTF16LE(src, src_len, dst, dst_len, bytes_copied, dstate);
    case CHARSET_UTF16BE:
        return DecodeUTF16BE(src, src_len, dst, dst_len, bytes_copied, dstate);
    case CHARSET_UTF32LE:
        return DecodeUTF32LE(src, src_len, dst, dst_len, bytes_copied, dstate);
    case CHARSET_UTF32BE:
        return DecodeUTF32BE(src, src_len, dst, dst_len, bytes_copied, dstate);
    }

    /* In case the function is called with a bad charset. */
    *bytes_copied = 0;
    return DECODE_UTF_FAILURE;
}

