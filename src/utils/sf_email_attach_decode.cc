//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
// Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>

#include "sf_email_attach_decode.h"

#include "snort_bounds.h"
#include "util.h"
#include "util_unfold.h"
#include "sf_base64decode.h"

#define UU_DECODE_CHAR(c) (((c) - 0x20) & 0x3f)

int sf_qpdecode(char* src, uint32_t slen, char* dst, uint32_t dlen, uint32_t* bytes_read,
    uint32_t* bytes_copied)
{
    char ch;

    if (!src || !slen || !dst || !dlen || !bytes_read || !bytes_copied )
        return -1;

    *bytes_read = 0;
    *bytes_copied = 0;

    while ( (*bytes_read < slen) && (*bytes_copied < dlen))
    {
        ch = src[*bytes_read];
        *bytes_read += 1;
        if ( ch == '=' )
        {
            if ( (*bytes_read < slen))
            {
                if (src[*bytes_read] == '\n')
                {
                    *bytes_read += 1;
                    continue;
                }
                else if ( *bytes_read < (slen - 1) )
                {
                    char ch1 = src[*bytes_read];
                    char ch2 = src[*bytes_read + 1];
                    if ( ch1 == '\r' && ch2 == '\n')
                    {
                        *bytes_read += 2;
                        continue;
                    }
                    if (isxdigit((int)ch1) && isxdigit((int)ch2))
                    {
                        char hexBuf[3];
                        char* eptr;
                        hexBuf[0] = ch1;
                        hexBuf[1] = ch2;
                        hexBuf[2] = '\0';
                        dst[*bytes_copied]= (char)strtoul(hexBuf, &eptr, 16);
                        if ((*eptr != '\0'))
                        {
                            return -1;
                        }
                        *bytes_read += 2;
                        *bytes_copied +=1;
                        continue;
                    }
                    dst[*bytes_copied] = ch;
                    *bytes_copied +=1;
                    continue;
                }
                else
                {
                    *bytes_read -= 1;
                    return 0;
                }
            }
            else
            {
                *bytes_read -= 1;
                return 0;
            }
        }
        else if ( isprint(ch) || isblank(ch) || ch == '\r' || ch == '\n' )
        {
            dst[*bytes_copied] = ch;
            *bytes_copied +=1;
        }
    }

    return 0;
}

int sf_uudecode(uint8_t* src, uint32_t slen, uint8_t* dst, uint32_t dlen, uint32_t* bytes_read,
    uint32_t* bytes_copied, uint8_t* begin_found, uint8_t* end_found)
{
    uint8_t* sod;
    int sol = 1, length = 0;
    uint8_t* ptr, * end, * dptr, * dend;

    if (!src || !slen || !dst || !dlen ||  !bytes_read || !bytes_copied || !begin_found ||
        !end_found )
        return -1;

    ptr = src;
    end = src + slen;
    dptr = dst;
    dend = dst + dlen;
    /* begin not found. Search for begin */
    if ( !(*begin_found) )
    {
        if ( slen < 5 )
        {
            /* Not enough data to search */
            *bytes_read = 0;
            *bytes_copied = 0;
            return 0;
        }
        else
        {
            sod = (uint8_t*)SnortStrnStr((const char*)src, 5, "begin");
            if (sod)
            {
                *begin_found = 1;
                /*begin str found. Move to the actual data*/
                ptr = (uint8_t*)SnortStrnStr((const char*)(sod), (end - sod), "\n");
                if ( !ptr )
                {
                    *bytes_read = slen;
                    *bytes_copied = 0;
                    return 0;
                }
            }
            else
            {
                /*Encoded data for UUencode should start with begin. Error encountered.*/
                return -1;
            }
        }
    }

    while ( (ptr < end) && (dptr < dend))
    {
        if (*ptr == '\n')
        {
            sol = 1;
            ptr++;
            continue;
        }

        if (sol)
        {
            sol = 0;
            length = UU_DECODE_CHAR(*ptr);

            if ( length <= 0 )
            {
                /* empty line with no encoded characters indicates end of output */
                break;
            }
            else if ( length == 5 )
            {
                if (*ptr == 'e')
                {
                    *end_found = 1;
                    break;
                }
            }
            /* check if destination buffer is big enough */
            if (( dend - dptr) < length)
            {
                length = dend - dptr;
            }

            length = (length * 4) / 3;

            /*check if src buffer has enough encoded data*/
            if ( (end - (ptr + 1)) < length)
            {
                /*not enough data to decode. We will wait for the next packet*/
                break;
            }

            ptr++;

            while ( length > 0 )
            {
                *dptr++ = (UU_DECODE_CHAR(ptr[0]) << 2) | (UU_DECODE_CHAR(ptr[1]) >> 4);
                ptr++;
                if (--length == 0 )
                    break;

                *dptr++ = (UU_DECODE_CHAR(ptr[0]) << 4) | (UU_DECODE_CHAR(ptr[1]) >> 2);
                ptr++;
                if (--length == 0)
                    break;

                *dptr++ = (UU_DECODE_CHAR(ptr[0]) << 6) | (UU_DECODE_CHAR(ptr[1]));
                ptr += 2;
                length -= 2;
            }
        }
        else
        {
            /* probably padding. skip over it.*/
            ptr++;
        }
    }

    if (*end_found)
        *bytes_read = end - src;
    else
        *bytes_read = ptr - src;
    *bytes_copied = dptr - dst;
    return 0;
}
