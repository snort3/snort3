//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// Writen by Bhagyashree Bantwal <bbantwal@sourcefire.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "util_unfold.h"

namespace snort
{
/* Given a string, removes header folding (\r\n followed by linear whitespace)
 * and exits when the end of a header is found, defined as \n followed by a
 * non-whitespace.  This is especially helpful for HTML.
 */
int sf_unfold_header(const uint8_t* inbuf, uint32_t inbuf_size, uint8_t* outbuf,
    uint32_t outbuf_size, uint32_t* output_bytes, int trim_spaces, int* folded)
{
    int num_spaces = 0;
    const uint8_t* cursor, * endofinbuf;
    uint8_t* outbuf_ptr;

    uint32_t n = 0;

    int httpheaderfolding = 0;
    int folding_present = 0;

    cursor = inbuf;
    endofinbuf = inbuf + inbuf_size;
    outbuf_ptr = outbuf;

    /* Keep adding chars until we get to the end of the line.  If we get to the
     * end of the line and the next line starts with a tab or space, add the space
     * to the buffer and keep reading.  If the next line does not start with a
     * tab or space, stop reading because that's the end of the header. */
    while ((cursor < endofinbuf) && (n < outbuf_size))
    {
        if (((*cursor == ' ') || (*cursor == '\t')))
        {
            if (folding_present)
                num_spaces++;
            if (httpheaderfolding)
            {
                num_spaces++;
                folding_present = 1;
                httpheaderfolding = 0;
            }
            else if (!trim_spaces)
            {
                /* Spaces are valid except after CRs */
                *outbuf_ptr++ = *cursor;
            }
        }
        else if ((*cursor == '\n') && (httpheaderfolding != 1))
        {
            /* Can't have multiple LFs in a row, but if we get one it
             * needs to be followed by at least one space */
            httpheaderfolding = 1;
        }
        else if ((*cursor == '\r') && !httpheaderfolding)
        {
            /* CR needs to be followed by LF and can't start a line */
            httpheaderfolding = 2;
        }
        else if (!httpheaderfolding)
        {
            *outbuf_ptr++ = *cursor;
            n++;
        }
        else
        {
            /* We have reached the end of the header
               Unless we get multiple CRs, which is suspicious, but not for us to decide */
            break;
        }
        cursor++;
    }
    if (n < outbuf_size)
        *outbuf_ptr = '\0';
    else
        outbuf[outbuf_size - 1] = '\0';

    *output_bytes = outbuf_ptr - outbuf;
    if (folded)
        *folded = num_spaces;
    return 0;
}

/* Strips the CRLF from the input buffer */

int sf_strip_CRLF(const uint8_t* inbuf, uint32_t inbuf_size, uint8_t* outbuf,
    uint32_t outbuf_size, uint32_t* output_bytes)
{
    const uint8_t* cursor, * endofinbuf;
    uint8_t* outbuf_ptr;
    uint32_t n = 0;

    if ( !inbuf || !outbuf)
        return -1;

    cursor = inbuf;
    endofinbuf = inbuf + inbuf_size;
    outbuf_ptr = outbuf;
    while ((cursor < endofinbuf) && (n < outbuf_size))
    {
        if ((*cursor != '\n') && (*cursor != '\r'))
        {
            *outbuf_ptr++ = *cursor;
            n++;
        }
        cursor++;
    }

    if (output_bytes)
        *output_bytes = outbuf_ptr - outbuf;

    return(0);
}

/* Strips the LWS at the end of line.
 * Only strips the LWS before LF or CRLF
 */

int sf_strip_LWS(const uint8_t* inbuf, uint32_t inbuf_size, uint8_t* outbuf,
    uint32_t outbuf_size, uint32_t* output_bytes)
{
    const uint8_t* cursor, * endofinbuf;
    uint8_t* outbuf_ptr;
    uint32_t n = 0;
    uint8_t lws = 0;

    if ( !inbuf || !outbuf)
        return -1;

    cursor = inbuf;
    endofinbuf = inbuf + inbuf_size;
    outbuf_ptr = outbuf;
    while ((cursor < endofinbuf) && (n < outbuf_size))
    {
        if ((*cursor != '\n') && (*cursor != '\r'))
        {
            if ((*cursor != ' ') && (*cursor != '\t'))
                lws = 0;
            else
                lws = 1;
            *outbuf_ptr++ = *cursor;
            n++;
        }
        else
        {
            if (lws)
            {
                lws = 0;
                while ( n > 0 )
                {
                    if ((*(outbuf_ptr-1) != ' ') && (*(outbuf_ptr-1) !='\t'))
                        break;
                    n--;
                    outbuf_ptr--;
                }
            }

            *outbuf_ptr++ = *cursor;
            n++;
        }
        cursor++;
    }

    if (output_bytes)
        *output_bytes = outbuf_ptr - outbuf;

    return(0);
}

}

