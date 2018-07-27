//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// http_cutter.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_cutter.h"

using namespace HttpEnums;

ScanResult HttpStartCutter::cut(const uint8_t* buffer, uint32_t length,
    HttpInfractions* infractions, HttpEventGen* events, uint32_t, uint32_t)
{
    for (uint32_t k = 0; k < length; k++)
    {
        // Discard magic six white space characters CR, LF, Tab, VT, FF, and SP when they occur
        // before the start line.
        // If we have seen nothing but white space so far ...
        if (num_crlf == octets_seen + k)
        {
            if (is_sp_tab_cr_lf_vt_ff[buffer[k]])
            {
                if (!is_cr_lf[buffer[k]])
                {
                    // tab, VT, FF, or space between messages
                    *infractions += INF_WS_BETWEEN_MSGS;
                    events->create_event(EVENT_WS_BETWEEN_MSGS);
                }
                if (num_crlf < MAX_LEADING_WHITESPACE)
                {
                    num_crlf++;
                    continue;
                }
                else
                {
                    *infractions += INF_TOO_MUCH_LEADING_WS;
                    events->generate_misformatted_http(buffer, length);
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
            // bindings. Passing is no guarantee that the connection is really HTTP, but failing
            // makes it clear that it isn't.
            switch (validate(buffer[k], infractions, events))
            {
            case V_GOOD:
                validated = true;
                break;
            case V_BAD:
                *infractions += INF_NOT_HTTP;
                events->generate_misformatted_http(buffer, length);
                return SCAN_ABORT;
            case V_TBD:
                break;
            }
        }
        if (buffer[k] == '\n')
        {
            num_crlf++;
            if (num_crlf == 1)
            {
                // There was no CR before this
                *infractions += INF_LF_WITHOUT_CR;
                events->create_event(EVENT_LF_WITHOUT_CR);
            }
            num_flush = k+1;
            return SCAN_FOUND;
        }
        if (num_crlf == 1)
        {   // CR not followed by LF
            *infractions += INF_CR_WITHOUT_LF;
            events->create_event(EVENT_CR_WITHOUT_LF);
            num_flush = k;                      // current octet not flushed
            return SCAN_FOUND;
        }
        if (buffer[k] == '\r')
        {
            num_crlf = 1;
        }
    }
    octets_seen += length;
    return SCAN_NOT_FOUND;
}

HttpStartCutter::ValidationResult HttpRequestCutter::validate(uint8_t octet, HttpInfractions*,
    HttpEventGen*)
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

HttpStartCutter::ValidationResult HttpStatusCutter::validate(uint8_t octet,
    HttpInfractions* infractions, HttpEventGen* events)
{
    // Status line must begin "HTTP/"
    static const int match_size = 5;
    static const uint8_t primary_match[match_size] = { 'H', 'T', 'T', 'P', '/' };
    static const uint8_t secondary_match[match_size] = { 'h', 't', 't', 'p', '/' };

    if (octet != primary_match[octets_checked])
    {
        if (octet == secondary_match[octets_checked])
        {
            // Lower case is wrong but we can still parse the message
            *infractions += INF_VERSION_NOT_UPPERCASE;
            events->create_event(EVENT_VERSION_NOT_UPPERCASE);
        }
        else
            return V_BAD;
    }
    if (++octets_checked >= match_size)
        return V_GOOD;
    return V_TBD;
}

ScanResult HttpHeaderCutter::cut(const uint8_t* buffer, uint32_t length,
    HttpInfractions* infractions, HttpEventGen* events, uint32_t, uint32_t)
{
    // Header separators: leading \r\n, leading \n, nonleading \r\n\r\n, nonleading \n\r\n,
    // nonleading \r\n\n, and nonleading \n\n. The separator itself becomes num_excess which is
    // discarded during reassemble().
    // \r without \n can (improperly) end the start line or a header line, but not the entire
    // header block.
    for (uint32_t k = 0; k < length; k++)
    {
        switch (state)
        {
        case ZERO:
            if (buffer[k] == '\r')
            {
                state = HALF;
                num_crlf++;
            }
            else if (buffer[k] == '\n')
            {
                *infractions += INF_LF_WITHOUT_CR;
                events->create_event(EVENT_LF_WITHOUT_CR);
                state = ONE;
                num_crlf++;
            }
            break;
        case HALF:
            if (buffer[k] == '\r')
            {
                *infractions += INF_CR_WITHOUT_LF;
                events->create_event(EVENT_CR_WITHOUT_LF);
                state = THREEHALF;
                num_crlf++;
            }
            else if (buffer[k] == '\n')
            {
                state = ONE;
                num_crlf++;
            }
            else
            {
                *infractions += INF_CR_WITHOUT_LF;
                events->create_event(EVENT_CR_WITHOUT_LF);
                state = ZERO;
                num_crlf = 0;
                num_head_lines++;
            }
            break;
        case ONE:
            if (buffer[k] == '\r')
            {
                state = THREEHALF;
                num_crlf++;
            }
            else if (buffer[k] == '\n')
            {
                *infractions += INF_LF_WITHOUT_CR;
                events->create_event(EVENT_LF_WITHOUT_CR);
                num_crlf++;
                num_flush = k + 1;
                return SCAN_FOUND;
            }
            else
            {
                state = ZERO;
                num_crlf = 0;
                num_head_lines++;
            }
            break;
        case THREEHALF:
            if (buffer[k] == '\r')
            {
                *infractions += INF_CR_WITHOUT_LF;
                events->create_event(EVENT_CR_WITHOUT_LF);
                num_crlf++;
            }
            else if (buffer[k] == '\n')
            {
                num_crlf++;
                num_flush = k + 1;
                return SCAN_FOUND;
            }
            else
            {
                *infractions += INF_CR_WITHOUT_LF;
                events->create_event(EVENT_CR_WITHOUT_LF);
                state = ZERO;
                num_crlf = 0;
                num_head_lines++;
            }
            break;
        }
    }
    octets_seen += length;
    return SCAN_NOT_FOUND;
}

ScanResult HttpBodyClCutter::cut(const uint8_t*, uint32_t length, HttpInfractions*,
    HttpEventGen*, uint32_t flow_target, uint32_t flow_max)
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
        num_flush = flow_target;
        remaining -= num_flush;
        return SCAN_FOUND_PIECE;
    }
}

ScanResult HttpBodyOldCutter::cut(const uint8_t*, uint32_t length, HttpInfractions*, HttpEventGen*,
    uint32_t flow_target, uint32_t)
{
    if (flow_target == 0)
    {
        // FIXIT-P Need StreamSplitter::END
        // With other types of body we would skip to the trailers and/or next message now. But this
        // will run to connection close so we should just stop processing this flow. But there is
        // no way to ask stream to do that so we must skip through the rest of the message
        // ourselves.
        num_flush = length;
        return SCAN_DISCARD_PIECE;
    }

    num_flush = flow_target;
    return SCAN_FOUND_PIECE;
}

ScanResult HttpBodyChunkCutter::cut(const uint8_t* buffer, uint32_t length,
    HttpInfractions* infractions, HttpEventGen* events, uint32_t flow_target, uint32_t)
{
    // Are we skipping through the rest of this chunked body to the trailers and the next message?
    const bool discard_mode = (flow_target == 0);

    for (int32_t k=0; k < static_cast<int32_t>(length); k++)
    {
        switch (curr_state)
        {
        case CHUNK_NEWLINES:
            // Looking for improper CRLFs before the chunk header
            if (is_cr_lf[buffer[k]])
            {
                *infractions += INF_CHUNK_BAD_SEP;
                events->create_event(EVENT_CHUNK_BAD_SEP);
                break;
            }
            curr_state = CHUNK_LEADING_WS;
            k--; // Reprocess this octet in the next state
            break;
        case CHUNK_LEADING_WS:
            // Looking for whitespace before the chunk size
            if (is_sp_tab[buffer[k]])
            {
                *infractions += INF_CHUNK_LEADING_WS;
                events->create_event(EVENT_CHUNK_WHITESPACE);
                num_leading_ws++;
                if (num_leading_ws == 5)
                {
                    events->create_event(EVENT_BROKEN_CHUNK);
                    curr_state = CHUNK_BAD;
                    k--;
                }
                break;
            }
            curr_state = CHUNK_ZEROS;
            k--;
            break;
        case CHUNK_ZEROS:
            // Looking for leading zeros in the chunk size.
            if (buffer[k] == '0')
            {
                num_zeros++;
                if (num_zeros == 5)
                {
                    *infractions += INF_CHUNK_ZEROS;
                    events->create_event(EVENT_CHUNK_ZEROS);
                }
                break;
            }
            curr_state = CHUNK_NUMBER;
            k--;
            break;
        case CHUNK_NUMBER:
            // Reading the chunk size
            if (buffer[k] == '\r')
            {
                curr_state = CHUNK_HCRLF;
            }
            else if (buffer[k] == '\n')
            {
                *infractions += INF_CHUNK_BARE_LF;
                events->create_event(EVENT_CHUNK_BARE_LF);
                curr_state = CHUNK_HCRLF;
                k--;
            }
            else if (is_sp_tab[buffer[k]])
            {
                *infractions += INF_CHUNK_WHITESPACE;
                events->create_event(EVENT_CHUNK_WHITESPACE);
                curr_state = CHUNK_TRAILING_WS;
            }
            else if (buffer[k] == ';')
            {
                *infractions += INF_CHUNK_OPTIONS;
                events->create_event(EVENT_CHUNK_OPTIONS);
                curr_state = CHUNK_OPTIONS;
            }
            else if (as_hex[buffer[k]] == -1)
            {
                // illegal character present in chunk length
                *infractions += INF_CHUNK_BAD_CHAR;
                events->create_event(EVENT_BROKEN_CHUNK);
                curr_state = CHUNK_BAD;
                k--;
            }
            else
            {
                expected = expected * 16 + as_hex[buffer[k]];
                if (++digits_seen > 8)
                {
                    // overflow protection: must fit into 32 bits
                    *infractions += INF_CHUNK_TOO_LARGE;
                    events->create_event(EVENT_BROKEN_CHUNK);
                    curr_state = CHUNK_BAD;
                    k--;
                }
            }
            break;
        case CHUNK_TRAILING_WS:
            // Skipping over improper whitespace following the chunk size
            if (buffer[k] == '\r')
            {
                curr_state = CHUNK_HCRLF;
            }
            else if (buffer[k] == '\n')
            {
                *infractions += INF_CHUNK_BARE_LF;
                events->create_event(EVENT_CHUNK_BARE_LF);
                curr_state = CHUNK_HCRLF;
                k--;
            }
            else if (buffer[k] == ';')
            {
                *infractions += INF_CHUNK_OPTIONS;
                events->create_event(EVENT_CHUNK_OPTIONS);
                curr_state = CHUNK_OPTIONS;
            }
            else if (!is_sp_tab[buffer[k]])
            {
                // illegal character present in chunk length
                *infractions += INF_CHUNK_BAD_CHAR;
                events->create_event(EVENT_BROKEN_CHUNK);
                curr_state = CHUNK_BAD;
                k--;
            }
            break;
        case CHUNK_OPTIONS:
            // The RFC permits options to follow the chunk size. No one normally does this.
            if (buffer[k] == '\r')
            {
                curr_state = CHUNK_HCRLF;
            }
            else if (buffer[k] == '\n')
            {
                *infractions += INF_CHUNK_BARE_LF;
                events->create_event(EVENT_CHUNK_BARE_LF);
                curr_state = CHUNK_HCRLF;
                k--;
            }
            break;
        case CHUNK_HCRLF:
            // The chunk header should end in CRLF and this should be the LF
            if (buffer[k] != '\n')
            {
                // This is qualitatively different from similar bare CR issues because it doesn't
                // provide a transparent data channel. A recipient is much less likely to implement
                // tolerance for this irregularity because a chunk that begins with LF is
                // ambiguous.
                *infractions += INF_CHUNK_LONE_CR;
                events->create_event(EVENT_BROKEN_CHUNK);
                curr_state = CHUNK_BAD;
                k--;
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
                *infractions += INF_CHUNK_NO_LENGTH;
                events->create_event(EVENT_BROKEN_CHUNK);
                curr_state = CHUNK_BAD;
                k--;
            }
            break;
        case CHUNK_DATA:
            // Moving through the chunk data
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
                data_seen = 0;
                num_flush = k+1;
                return SCAN_FOUND_PIECE;
            }
            break;
          }
        case CHUNK_DCRLF1:
            // The CR from the end-of-chunk CRLF should be here
            if (buffer[k] == '\r')
            {
                curr_state = CHUNK_DCRLF2;
            }
            else if (buffer[k] == '\n')
            {
                *infractions += INF_CHUNK_BAD_SEP;
                events->create_event(EVENT_CHUNK_BAD_SEP);
                curr_state = CHUNK_DCRLF2;
                k--;
            }
            else
            {
                *infractions += INF_CHUNK_BAD_END;
                events->create_event(EVENT_BROKEN_CHUNK);
                curr_state = CHUNK_BAD;
                k--;
            }
            break;
        case CHUNK_DCRLF2:
            // The LF from the end-of-chunk CRLF should be here
            num_good_chunks++;
            num_leading_ws = 0;
            num_zeros = 0;
            expected = 0;
            digits_seen = 0;
            curr_state = CHUNK_NEWLINES;
            if (buffer[k] == '\n')
                break;
            *infractions += INF_CHUNK_BAD_SEP;
            events->create_event(EVENT_CHUNK_BAD_SEP);
            if (buffer[k] != '\r')
                k--;
            break;
        case CHUNK_BAD:
            // Chunk reassembly has failed. This is a terminal state but inspection of the body
            // must go on.
            // If we are skipping to the trailers and next message the broken chunk thwarts us
            if (discard_mode)
            {
                // FIXIT-P Need StreamSplitter::END
                // With the broken chunk this will run to connection close so we should just stop
                // processing this flow. But there is no way to ask stream to do that so we must
                // skip through the rest of the message ourselves.
                num_flush = length;
                return SCAN_DISCARD_PIECE;
            }

            // When chunk parsing breaks down and we first enter CHUNK_BAD state, it may happen
            // that there were chunk header bytes between the last good chunk and the point where
            // the failure occurred. These will not have been counted in data_seen because we
            // planned to delete them during reassembly. Because they are not part of a valid chunk
            // they will be reassembled after all. This will overrun the flow_target making the
            // message section a little bigger than planned. It's not important.
            uint32_t skip_amount = length-k;
            skip_amount = (skip_amount <= flow_target-data_seen) ? skip_amount :
                flow_target-data_seen;
            k += skip_amount - 1;
            if ((data_seen += skip_amount) == flow_target)
            {
                data_seen = 0;
                num_flush = k+1;
                return SCAN_FOUND_PIECE;
            }
            break;
        }
    }
    if (discard_mode)
    {
        num_flush = length;
        return SCAN_DISCARD_PIECE;
    }

    octets_seen += length;
    return SCAN_NOT_FOUND;
}

