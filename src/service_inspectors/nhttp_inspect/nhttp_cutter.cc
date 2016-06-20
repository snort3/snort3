//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_cutter.cc author Tom Peters <thopeter@cisco.com>

#include "nhttp_cutter.h"

using namespace NHttpEnums;

ScanResult NHttpStartCutter::cut(const uint8_t* buffer, uint32_t length,
    NHttpInfractions& infractions, NHttpEventGen& events, uint32_t, uint32_t)
{
    for (uint32_t k = 0; k < length; k++)
    {
        // Discard magic six white space characters CR, LF, Tab, VT, FF, and SP when they occur
        // before the start line.
        // If we have seen nothing but white space so far ...
        if (num_crlf == octets_seen + k)
        {
            if ((buffer[k] == ' ') || ((buffer[k] >= '\t') && (buffer[k] <= '\r')))
            {
                if ((buffer[k] != '\n') && (buffer[k] != '\r'))
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
                    events.generate_misformatted_http(buffer, length);
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
            // The purpose of validate() is to quickly and efficiently dispose of obviously wrong
            // bindings. Passing is no guarentee that the connection is really HTTP, but failing
            // makes it clear that it isn't.
            switch (validate(buffer[k]))
            {
            case V_GOOD:
                validated = true;
                break;
            case V_BAD:
                infractions += INF_NOT_HTTP;
                events.generate_misformatted_http(buffer, length);
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
        if (num_crlf == 1)
        {   // CR not followed by LF
            infractions += INF_LONE_CR;
            events.generate_misformatted_http(buffer, length);
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

NHttpStartCutter::ValidationResult NHttpRequestCutter::validate(uint8_t octet)
{
    // Request line must begin with a method. There is no list of all possible methods because
    // extension is allowed, so there is no absolute way to tell whether something is a method.
    // Instead we verify that all its characters are drawn from the RFC list of valid token
    // characters, that it is followed by a whitespace character, and that it is at most 80
    // characters long. There is nothing special or specified about 80. It is just more than any
    // reasonable method name would be.

    static const int max_method_length = 80;

    if ((octet == ' ') || (octet == '\t'))
        return V_GOOD;
    if (!token_char[octet] || ++octets_checked > max_method_length)
        return V_BAD;
    return V_TBD;
}

NHttpStartCutter::ValidationResult NHttpStatusCutter::validate(uint8_t octet)
{
    // Status line must begin "HTTP/"
    static const int match_size = 5;
    static const uint8_t match[match_size] = { 'H', 'T', 'T', 'P', '/' };

    if (octet != match[octets_checked++])
        return V_BAD;
    if (octets_checked >= match_size)
        return V_GOOD;
    return V_TBD;
}

ScanResult NHttpHeaderCutter::cut(const uint8_t* buffer, uint32_t length,
    NHttpInfractions& infractions, NHttpEventGen& events, uint32_t, uint32_t)
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

ScanResult NHttpBodyClCutter::cut(const uint8_t*, uint32_t length, NHttpInfractions&,
    NHttpEventGen&, uint32_t flow_target, uint32_t flow_max)
{
    assert(remaining > 0);

    // Are we skipping to the next message?
    if (flow_target == 0)
    {
        if (remaining <= length)
        {
            num_flush = remaining;
            remaining = 0;
            return SCAN_DISCARD;
        }
        else
        {
            num_flush = length;
            remaining -= num_flush;
            return SCAN_DISCARD_PIECE;
        }
    }

    // The normal body section size is flow_target. But if there are only flow_max or less
    // remaining we take the whole thing rather than leave a small final section.
    if (remaining <= flow_max)
    {
        num_flush = remaining;
        remaining = 0;
        return SCAN_FOUND;
    }
    else
    {
        // FIXIT-M need to implement random increments
        num_flush = flow_target;
        remaining -= num_flush;
        return SCAN_FOUND_PIECE;
    }
}

ScanResult NHttpBodyOldCutter::cut(const uint8_t*, uint32_t, NHttpInfractions&, NHttpEventGen&,
    uint32_t flow_target, uint32_t)
{
    if (flow_target == 0)
    {
        // With other types of body we could skip to the next message now. But this body will run
        // to connection close so we just stop.
        return SCAN_END;
    }

    // FIXIT-M need to implement random increments
    num_flush = flow_target;
    return SCAN_FOUND_PIECE;
}

ScanResult NHttpBodyChunkCutter::cut(const uint8_t* buffer, uint32_t length,
    NHttpInfractions& infractions, NHttpEventGen& events, uint32_t flow_target, uint32_t)
{
    // Are we skipping through the rest of this chunked body to the trailers and the next message?
    const bool discard_mode = (flow_target == 0);

    if (new_section)
    {
        new_section = false;
        octets_seen = 0;
        num_good_chunks = 0;
    }

    for (uint32_t k=0; k < length; k++)
    {
        switch (curr_state)
        {
        case CHUNK_ZEROS:
            if (buffer[k] == '0')
            {
                num_zeros++;
                if (num_zeros == 5)
                {
                    infractions += INF_CHUNK_ZEROS;
                    events.create_event(EVENT_CHUNK_ZEROS);
                }
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
            if (is_sp_tab[buffer[k]])
            {
                infractions += INF_CHUNK_WHITESPACE;
                events.create_event(EVENT_CHUNK_WHITESPACE);
                curr_state = CHUNK_WHITESPACE;
                break;
            }
            if (buffer[k] == ';')
            {
                infractions += INF_CHUNK_OPTIONS;
                events.create_event(EVENT_CHUNK_OPTIONS);
                curr_state = CHUNK_OPTIONS;
                break;
            }
            if (as_hex[buffer[k]] == -1)
            {
                // illegal character present in chunk length
                infractions += INF_CHUNK_BAD_CHAR;
                events.create_event(EVENT_BROKEN_CHUNK);
                curr_state = CHUNK_BAD;
                break;
            }
            expected = expected * 16 + as_hex[buffer[k]];
            if (++digits_seen > 8)
            {
                // overflow protection: must fit into 32 bits
                infractions += INF_CHUNK_TOO_LARGE;
                events.create_event(EVENT_BROKEN_CHUNK);
                curr_state = CHUNK_BAD;
                break;
            }
            break;
        case CHUNK_WHITESPACE:
            if (buffer[k] == '\r')
            {
                curr_state = CHUNK_HCRLF;
                break;
            }
            if (buffer[k] == ';')
            {
                infractions += INF_CHUNK_OPTIONS;
                events.create_event(EVENT_CHUNK_OPTIONS);
                curr_state = CHUNK_OPTIONS;
                break;
            }
            if (!is_sp_tab[buffer[k]])
            {
                // illegal character present in chunk length
                infractions += INF_CHUNK_BAD_CHAR;
                events.create_event(EVENT_BROKEN_CHUNK);
                curr_state = CHUNK_BAD;
                break;
            }
            break;
        case CHUNK_OPTIONS:
            if (buffer[k] == '\r')
            {
                curr_state = CHUNK_HCRLF;
            }
            else if (buffer[k] == '\n')
            {
                // FIXIT-L better to keep parsing chunks after bare LF (several changes needed)?
                infractions += INF_CHUNK_BARE_LF;
                events.create_event(EVENT_BROKEN_CHUNK);
                curr_state = CHUNK_BAD;
                break;
            }
            break;
        case CHUNK_HCRLF:
            if (buffer[k] != '\n')
            {
                infractions += INF_CHUNK_LONE_CR;
                events.create_event(EVENT_BROKEN_CHUNK);
                curr_state = CHUNK_BAD;
                break;
            }
            if (expected > 0)
            {
                curr_state = CHUNK_DATA;
            }
            else if (num_zeros > 0)
            {
                // Terminating zero-length chunk
                num_good_chunks++;
                num_flush = k+1;
                return !discard_mode ? SCAN_FOUND : SCAN_DISCARD;
            }
            else
            {
                infractions += INF_CHUNK_NO_LENGTH;
                events.create_event(EVENT_BROKEN_CHUNK);
                curr_state = CHUNK_BAD;
                break;
            }
            break;
        case CHUNK_DATA:
          {
            uint32_t skip_amount = (length-k <= expected) ? length-k : expected;
            if (!discard_mode && (skip_amount > flow_target-data_seen))
            { // Do not exceed requested section size
                skip_amount = flow_target-data_seen;
            }
            k += skip_amount - 1;
            if ((expected -= skip_amount) == 0)
            {
                curr_state = CHUNK_DCRLF1;
            }
            if ((data_seen += skip_amount) == flow_target)
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
                infractions += INF_CHUNK_BAD_END;
                events.create_event(EVENT_BROKEN_CHUNK);
                curr_state = CHUNK_BAD;
                break;
            }
            curr_state = CHUNK_DCRLF2;
            break;
        case CHUNK_DCRLF2:
            if (buffer[k] != '\n')
            {
                infractions += INF_CHUNK_BAD_END;
                events.create_event(EVENT_BROKEN_CHUNK);
                curr_state = CHUNK_BAD;
                break;
            }
            num_good_chunks++;
            curr_state = CHUNK_ZEROS;
            num_zeros = 0;
            expected = 0;
            digits_seen = 0;
            break;
        case CHUNK_BAD:
            // If we are skipping to the trailers and next message the broken chunk thwarts us
            if (discard_mode)
            {
                return SCAN_ABORT;
            }
            uint32_t skip_amount = length-k;
            skip_amount = (skip_amount <= flow_target-data_seen) ? skip_amount :
                flow_target-data_seen;
            k += skip_amount - 1;
            if ((data_seen += skip_amount) == flow_target)
            {
                // FIXIT-M need to randomize slice point
                data_seen = 0;
                num_flush = k+1;
                new_section = true;
                return SCAN_FOUND_PIECE;
            }
            break;
        }
    }
    octets_seen += length;
    if (discard_mode)
    {
        num_flush = length;
        return SCAN_DISCARD_PIECE;
    }
    return SCAN_NOTFOUND;
}

