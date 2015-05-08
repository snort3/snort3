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
                if ((buffer[k] != 10) && (buffer[k] != 13))
                {
                    // tab, VT, FF, or space between messages
                    infractions += INF_WS_BETWEEN_MSGS;
                    events.create_event(EVENT_WS_BETWEEN_MSGS);
                }
                if (num_crlf < MAX_LEADING_WHITESPACE)
                {
                    num_crlf++;
                    continue;
                }
                else
                {
                    infractions += INF_TOO_MUCH_LEADING_WS;
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
        if (!validated)
        {
            switch (validate(buffer[k]))
            {
            case V_GOOD:
                validated = true;
                break;
            case V_BAD:
                infractions += INF_NOT_HTTP;
                events.create_event(EVENT_NOT_HTTP);
                return SCAN_ABORT;
            case V_TBD:
                break;
            }
        }
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

NHttpStartSplitter::ValidationResult NHttpRequestSplitter::validate(uint8_t octet)
{
    static const int max_method_length = 80;

    if ((octet == ' ') || (octet == '\t'))
        return V_GOOD;
    if (!token_char[octet] || ++octets_checked > max_method_length)
        return V_BAD;
    return V_TBD;
}

NHttpStartSplitter::ValidationResult NHttpStatusSplitter::validate(uint8_t octet)
{
    static const int match_size = 5;
    static const uint8_t match[match_size] = { 'H', 'T', 'T', 'P', '/' };

    if (octet != match[octets_checked++])
        return V_BAD;
    if (octets_checked >= match_size)
        return V_GOOD;
    return V_TBD;
}

ScanResult NHttpHeaderSplitter::split(const uint8_t* buffer, uint32_t length,
    NHttpInfractions& infractions, NHttpEventGen& events)
{
    // Header separators: leading \r\n, leading \n, nonleading \r\n\r\n, nonleading \n\r\n,
    // nonleading \r\n\n, and nonleading \n\n. The separator itself becomes num_excess which is
    // discarded during reassemble().
    for (uint32_t k = 0; k < length; k++)
    {
        if (buffer[k] == '\n')
        {
            num_crlf++;
            if ((first_lf == 0) && (num_crlf < octets_seen + k + 1))
            {
                first_lf = num_crlf;
                // This count is here so the inspector can quickly allocate memory to store the
                // header lines. It doesn't allow for line wrapping because that is not important
                // for this purpose.
                num_head_lines++;
            }
            else
            {
                // Alert on \n not preceded by \r. Correct cases are \r\n\r\n and \r\n.
                if (!((num_crlf == 4) || ((num_crlf == 2) && (first_lf == 0))))
                {
                    infractions += INF_LF_WITHOUT_CR;
                    events.create_event(EVENT_IIS_DELIMITER);
                }
                num_flush = k + 1;
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
    octets_seen += length;
    return SCAN_NOTFOUND;
}

ScanResult NHttpBodySplitter::split(const uint8_t*, uint32_t, NHttpInfractions&, NHttpEventGen&)
{
    assert(remaining > 0);

    // The normal body section size is about 16K. But if there are only 24K or less remaining we
    // take the whole thing rather than leave a small final section.
    if (remaining <= FINAL_BLOCK_SIZE)
    {
        num_flush = remaining;
        remaining = 0;
        return SCAN_FOUND;
    }
    else
    {
        // FIXIT-M need to implement random increments
        num_flush = DATA_BLOCK_SIZE;
        remaining -= num_flush;
        return SCAN_FOUND_PIECE;
    }
}

ScanResult NHttpChunkSplitter::split(const uint8_t* buffer, uint32_t length,
    NHttpInfractions&, NHttpEventGen&)
{
    if (new_section)
    {
        new_section = false;
        octets_seen = 0;
    }

    for (uint32_t k=0; k < length; k++)
    {
        switch (curr_state)
        {
        case CHUNK_ZEROS:
            if (buffer[k] == '0')
            {
                num_zeros++;
                // FIXIT-L add test and alert for excessive zeros
                break;
            }
            curr_state = CHUNK_NUMBER;
            // Fall through
        case CHUNK_NUMBER:
            if (buffer[k] == '\r')
            {
                curr_state = CHUNK_HCRLF;
                break;
            }
            if (buffer[k] == ';')
            {
                // FIXIT-L add alert for option use
                curr_state = CHUNK_OPTIONS;
                break;
            }
            if (as_hex[buffer[k]] == -1)
            {
                // illegal character present in chunk length
                // FIXIT-L add alert for loss of sync
                num_flush = k + 1;
                return SCAN_FLUSH_ABORT;
            }
            expected = expected * 16 + as_hex[buffer[k]];
            if (++digits_seen > 8)
            {
                // overflow protection: must fit into 32 bits
                // FIXIT-L add alert for too large chunk size
                num_flush = k + 1;
                return SCAN_FLUSH_ABORT;
            }
            break;
        case CHUNK_OPTIONS:
            if (buffer[k] == '\r')
            {
                curr_state = CHUNK_HCRLF;
            }
            else if (buffer[k] == '\n')
            {
                // FIXIT-L add alert for loss of sync
                num_flush = k + 1;
                return SCAN_FLUSH_ABORT;
            }
            break;
        case CHUNK_HCRLF:
            if (buffer[k] != '\n')
            {
                // FIXIT-L add alert for loss of sync
                num_flush = k + 1;
                return SCAN_FLUSH_ABORT;
            }
            if (expected > 0)
            {
                curr_state = CHUNK_DATA;
            }
            else if (num_zeros > 0)
            {
                // Terminating zero-length chunk
                num_flush = k + 1;
                return SCAN_FOUND;
            }
            else
            {
                // FIXIT-L add alert for loss of sync
                num_flush = k + 1;
                return SCAN_FLUSH_ABORT;
            }
            break;
        case CHUNK_DATA:
          {
            uint32_t skip_amount = (length-k <= expected) ? length-k : expected;
            skip_amount = (skip_amount <= DATA_BLOCK_SIZE-data_seen) ? skip_amount :
                DATA_BLOCK_SIZE-data_seen;
            k += skip_amount - 1;
            if ((expected -= skip_amount) == 0)
            {
                curr_state = CHUNK_DCRLF1;
            }
            if ((data_seen += skip_amount) == DATA_BLOCK_SIZE)
            {
                // FIXIT-M need to randomize slice point
                data_seen = 0;
                num_flush = k+1;
                new_section = true;
                return SCAN_FOUND_PIECE;
            }
            break;
          }
        case CHUNK_DCRLF1:
            if (buffer[k] != '\r')
            {
                // FIXIT-L add alert for CRLF error
                num_flush = k + 1;
                return SCAN_FLUSH_ABORT;
            }
            curr_state = CHUNK_DCRLF2;
            break;
        case CHUNK_DCRLF2:
            if (buffer[k] != '\n')
            {
                // FIXIT-L add alert for CRLF error
                num_flush = k + 1;
                return SCAN_FLUSH_ABORT;
            }
            curr_state = CHUNK_ZEROS;
            num_zeros = 0;
            expected = 0;
            digits_seen = 0;
            break;
        }
    }
    octets_seen += length;
    return SCAN_NOTFOUND;
}

