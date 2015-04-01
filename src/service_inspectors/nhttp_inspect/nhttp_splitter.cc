//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_splitter.cc author Tom Peters <thopeter@cisco.com>

#include "nhttp_splitter.h"

using namespace NHttpEnums;

ScanResult NHttpStartSplitter::split(const uint8_t* buffer, uint32_t length,
    NHttpInfractions& infractions, NHttpEventGen& events)
{
    for (uint32_t k = 0; k < length; k++)
    {
        // Discard magic six white space characters CR, LF, Tab, VT, FF, and SP when they occur
        // before the start line.
        // If we have seen nothing but white space so far ...
        if (num_crlf == octets_seen + k)
        {
            if ((buffer[k] == 32) || ((buffer[k] >= 9) && (buffer[k] <= 13)))
            {
                if (num_crlf < MAX_LEADING_WHITESPACE)
                {
                    num_crlf++;
                    continue;
                }
                else
                {
                    infractions += INF_TOOMUCHLEADINGWS;
                    events.create_event(EVENT_LOSS_OF_SYNC);
                    return SCAN_ABORT;
                }
            }
            if (num_crlf > 0)
            {
                num_flush = k;     // current octet not flushed with white space
                return SCAN_DISCARD;
            }
        }

        // If we get this far then the leading white space issue is behind us and num_crlf was
        // reset to zero
        if (buffer[k] == '\n')
        {
            num_crlf++;
            num_flush = k+1;
            return SCAN_FOUND;
        }
        if (num_crlf == 1)   // FIXIT-M there needs to be an event for this
        {   // CR not followed by LF
            return SCAN_ABORT;
        }
        if (buffer[k] == '\r')
        {
            num_crlf = 1;
        }
    }
    octets_seen += length;
    return SCAN_NOTFOUND;
}

ScanResult NHttpHeaderSplitter::split(const uint8_t* buffer, uint32_t length,
    NHttpInfractions& infractions, NHttpEventGen& events)
{
    if (peek_status == SCAN_FOUND)
    {
        return SCAN_FOUND;
    }
    buffer += peek_octets;
    length -= peek_octets;

    // Header separators: leading \r\n, leading \n, nonleading \r\n\r\n, nonleading \n\r\n,
    // nonleading \r\n\n, and nonleading \n\n. The separator itself becomes num_excess which is
    // discarded during reassemble().
    // FIXIT-L There is a regression test with a rule that looks for these separators in the
    // header buffer.
    for (uint32_t k = 0; k < length; k++)
    {
        if (buffer[k] == '\n')
        {
            num_crlf++;
            if ((first_lf == 0) && (num_crlf < octets_seen + k + 1))
            {
                first_lf = num_crlf;
            }
            else
            {
                // Alert on \n not preceded by \r. Correct cases are \r\n\r\n and \r\n.
                if (!((num_crlf == 4) || ((num_crlf == 2) && (first_lf == 0))))
                {
                    infractions += INF_LFWITHOUTCR;
                    events.create_event(EVENT_IIS_DELIMITER);
                }
                num_flush = k + 1 + peek_octets;
                return SCAN_FOUND;
            }
        }
        else if (buffer[k] == '\r')
        {
            if (num_crlf == first_lf)
            {
                num_crlf++;
            }
            else
            {
                num_crlf = 1;
                first_lf = 0;
            }
        }
        else
        {
            num_crlf = 0;
            first_lf = 0;
        }
    }
    peek_octets = 0;
    octets_seen += length;
    return SCAN_NOTFOUND;
}

ScanResult NHttpHeaderSplitter::peek(const uint8_t* buffer, uint32_t length,
    NHttpInfractions& infractions, NHttpEventGen& events)
{
    peek_status = split(buffer, length, infractions, events);
    peek_octets = length;
    return peek_status;
}

ScanResult NHttpChunkSplitter::split(const uint8_t* buffer, uint32_t length,
    NHttpInfractions&, NHttpEventGen&)
{
    // FIXIT-M when things go wrong and we must abort we need to flush partial chunk buffer
    if (header_complete)
    {
        // Previously read the chunk header. Now just flush the length.
        num_flush = expected_length;
        return SCAN_FOUND;
    }
    for (uint32_t k = 0; k < length; k++)
    {
        // FIXIT-M learn to support white space before chunk header extension semicolon
        if (buffer[k] == '\n')
        {
            if (octets_seen + k == num_crlf)
            {
                // \r\n or \n leftover from previous chunk
                num_flush = k+1;
                return SCAN_DISCARD;
            }
            if (!length_started)
            {
                // chunk header specifies no length
                return SCAN_ABORT;
            }
            if (expected_length == 0)
            {
                // Workaround because stream cannot handle zero-length flush. Instead of flushing
                // the zero-length chunk to flush the partial chunk buffer in reassembly, we save
                // the terminal \n from the chunk header for use as an end-of-chunks signal.
                // FIXIT-M
                expected_length = 1;
                zero_chunk = true;
                num_flush = k;
            }
            else
            {
                num_flush = k+1;
            }
            // flush completed chunk header
            header_complete = true;
            return SCAN_DISCARD_CONTINUE;
        }
        if (num_crlf == 1)
        {
            // CR not followed by LF
            return SCAN_ABORT;
        }
        if (buffer[k] == '\r')
        {
            num_crlf = 1;
            continue;
        }
        if (buffer[k] == ';')
        {
            semicolon = true;
        }
        if (semicolon)
        {
            // we don't look at chunk header extensions
            continue;
        }
        if (as_hex[buffer[k]] == -1)
        {
            // illegal character present in chunk length
            return SCAN_ABORT;
        }
        length_started = true;
        if (digits_seen >= 8)
        {
            // overflow protection: must fit into 32 bits
            return SCAN_ABORT;
        }
        expected_length = expected_length * 16 + as_hex[buffer[k]];
        if (expected_length > 0)
        {
            // leading zeroes don't count
            digits_seen++;
        }
    }
    octets_seen += length;
    return SCAN_NOTFOUND;
}

