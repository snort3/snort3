//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#include "http_common.h"
#include "http_enum.h"
#include "http_flow_data.h"
#include "http_module.h"

using namespace HttpEnums;
using namespace HttpCommon;

ScanResult HttpStartCutter::cut(const uint8_t* buffer, uint32_t length,
    HttpInfractions* infractions, HttpEventGen* events, uint32_t, bool, HXBodyState)
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
                    events->create_event(HttpEnums::EVENT_TOO_MUCH_LEADING_WS);
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

HttpStartCutter::ValidationResult HttpRequestCutter::validate(uint8_t octet,
    HttpInfractions* infractions, HttpEventGen* events)
{
    // Request line must begin with a method. There is no list of all possible methods because
    // extension is allowed, so there is no absolute way to tell whether something is a method.
    // Instead we verify that all its characters are drawn from the RFC list of valid token
    // characters, that it is followed by a whitespace character, and that it is at most 80
    // characters long. There is nothing special or specified about 80. It is just more than any
    // reasonable method name would be. Additionally we check for the first 16 bytes of the HTTP/2
    // connection preface, which would otherwise pass the aforementioned check.

    static const int max_method_length = 80;
    static const int preface_len = 16;
    static const int h1_test_len_in_preface = 4;
    static const uint8_t h2_connection_preface[] = { 'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T',
        'P', '/', '2', '.', '0', '\r', '\n' };

    if (check_h2)
    {
        if (octet == h2_connection_preface[octets_checked])
        {
            octets_checked++;
            if (octets_checked >= preface_len)
            {
                *infractions += INF_HTTP2_IN_HI;
                events->create_event(HttpEnums::EVENT_UNEXPECTED_H2_PREFACE);
                return V_BAD;
            }
            return V_TBD;
        }
        else
        {
            if (octets_checked >= h1_test_len_in_preface)
                return V_GOOD;
            check_h2 = false;
        }
    }
    if ((octet == ' ') || (octet == '\t'))
        return V_GOOD;
    if (!token_char[octet] || ++octets_checked > max_method_length)
    {
        events->create_event(HttpEnums::EVENT_BAD_REQ_LINE);
        return V_BAD;
    }
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
        {
            events->create_event(HttpEnums::EVENT_BAD_STAT_LINE);
            return V_BAD;
        }
    }
    if (++octets_checked >= match_size)
        return V_GOOD;
    return V_TBD;
}

ScanResult HttpHeaderCutter::cut(const uint8_t* buffer, uint32_t length,
    HttpInfractions* infractions, HttpEventGen* events, uint32_t, bool, HXBodyState)
{
    // Header separators: leading \r\n, leading \n, leading \r\r\n, nonleading \r\n\r\n, nonleading
    // \n\r\n, nonleading \r\r\n, nonleading \r\n\n, and nonleading \n\n. The separator itself
    // becomes num_excess which is discarded during reassemble().
    // \r without \n can (improperly) end the start line or a header line, but not the entire
    // header block.
    // The leading cases work as described because the initial state is ONE.
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

HttpBodyCutter::HttpBodyCutter(bool accelerated_blocking_, ScriptFinder* finder_,
    CompressId compression_)
    : accelerated_blocking(accelerated_blocking_), compression(compression_), finder(finder_)
{
    if (accelerated_blocking)
    {
        if ((compression == CMP_GZIP) || (compression == CMP_DEFLATE))
        {
            compress_stream = new z_stream;
            compress_stream->zalloc = Z_NULL;
            compress_stream->zfree = Z_NULL;
            compress_stream->next_in = Z_NULL;
            compress_stream->avail_in = 0;
            const int window_bits = (compression == CMP_GZIP) ?
                GZIP_WINDOW_BITS : DEFLATE_WINDOW_BITS;
            if (inflateInit2(compress_stream, window_bits) != Z_OK)
            {
                assert(false);
                compression = CMP_NONE;
                delete compress_stream;
                compress_stream = nullptr;
            }
        }

        static const uint8_t inspect_string[] = { '<', '/', 's', 'c', 'r', 'i', 'p', 't', '>' };
        static const uint8_t inspect_upper[] = { '<', '/', 'S', 'C', 'R', 'I', 'P', 'T', '>' };

        match_string = inspect_string;
        match_string_upper = inspect_upper;
        string_length = sizeof(inspect_string);
    }
}

HttpBodyCutter::~HttpBodyCutter()
{
    if (compress_stream != nullptr)
    {
        inflateEnd(compress_stream);
        delete compress_stream;
    }
}

ScanResult HttpBodyClCutter::cut(const uint8_t* buffer, uint32_t length, HttpInfractions*,
    HttpEventGen*, uint32_t flow_target, bool stretch, HXBodyState)
{
    assert(remaining > octets_seen);

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

    // A target that is bigger than the entire rest of the message body makes no sense
    if (remaining <= flow_target)
    {
        flow_target = remaining;
        stretch = false;
    }

    if (octets_seen + length < flow_target)
    {
        octets_seen += length;
        return need_accelerated_blocking(buffer, length) ?
            SCAN_NOT_FOUND_ACCELERATE : SCAN_NOT_FOUND;
    }

    if (!stretch)
    {
        remaining -= flow_target;
        num_flush = flow_target - octets_seen;
        if (remaining > 0)
        {
            need_accelerated_blocking(buffer, num_flush);
            return SCAN_FOUND_PIECE;
        }
        else
            return SCAN_FOUND;
    }

    if (octets_seen + length < remaining)
    {
        // The message body continues beyond this segment
        // Stretch the section to include this entire segment provided it is not too big
        if (octets_seen + length <= flow_target + MAX_SECTION_STRETCH)
            num_flush = length;
        else
            num_flush = flow_target - octets_seen;
        remaining -= octets_seen + num_flush;
        need_accelerated_blocking(buffer, num_flush);
        return SCAN_FOUND_PIECE;
    }

    if (remaining - flow_target <= MAX_SECTION_STRETCH)
    {
        // Stretch the section to finish the message body
        num_flush = remaining - octets_seen;
        remaining = 0;
        return SCAN_FOUND;
    }

    // Cannot stretch to the end of the message body. Cut at the original target.
    num_flush = flow_target - octets_seen;
    remaining -= flow_target;
    need_accelerated_blocking(buffer, num_flush);
    return SCAN_FOUND_PIECE;
}

ScanResult HttpBodyOldCutter::cut(const uint8_t* buffer, uint32_t length, HttpInfractions*,
    HttpEventGen*, uint32_t flow_target, bool stretch, HXBodyState)
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

    if (octets_seen + length < flow_target)
    {
        // Not enough data yet to create a message section
        octets_seen += length;
        return need_accelerated_blocking(buffer, length) ?
            SCAN_NOT_FOUND_ACCELERATE : SCAN_NOT_FOUND;
    }
    else if (stretch && (octets_seen + length <= flow_target + MAX_SECTION_STRETCH))
    {
        // Cut the section at the end of this TCP segment to avoid splitting a packet
        num_flush = length;
        need_accelerated_blocking(buffer, num_flush);
        return SCAN_FOUND_PIECE;
    }
    else
    {
        // Cut the section at the target length. Either stretching is not allowed or the end of
        // the segment is too far away.
        num_flush = flow_target - octets_seen;
        need_accelerated_blocking(buffer, num_flush);
        return SCAN_FOUND_PIECE;
    }
}

void HttpBodyChunkCutter::transition_to_chunk_bad(bool& accelerate_this_packet)
{
    curr_state = CHUNK_BAD;
    accelerate_this_packet = true;
    zero_chunk = false;
}

ScanResult HttpBodyChunkCutter::cut(const uint8_t* buffer, uint32_t length,
    HttpInfractions* infractions, HttpEventGen* events, uint32_t flow_target, bool stretch,
    HXBodyState)
{
    // Are we skipping through the rest of this chunked body to the trailers and the next message?
    const bool discard_mode = (flow_target == 0);

    const uint32_t adjusted_target = stretch ? MAX_SECTION_STRETCH + flow_target : flow_target;

    bool accelerate_this_packet = false;

    for (int32_t k=0; k < static_cast<int32_t>(length); k++)
    {
        switch (curr_state)
        {
        case CHUNK_NEWLINES:
            zero_chunk = true;
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
                    transition_to_chunk_bad(accelerate_this_packet);
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
                transition_to_chunk_bad(accelerate_this_packet);
                k--;
            }
            else
            {
                expected = expected * 16 + as_hex[buffer[k]];
                if ((++digits_seen > 8) || (expected > maximum_chunk_length))
                {
                    // alert for exceeding configurable limit
                    *infractions += INF_CHUNK_OVER_MAXIMUM;
                    events->create_event(EVENT_LARGE_CHUNK);
                    if (digits_seen > 8)
                    {
                        // overflow protection: absolutely must fit into 32 bits
                        *infractions += INF_CHUNK_TOO_LARGE;
                        events->create_event(EVENT_BROKEN_CHUNK);
                        transition_to_chunk_bad(accelerate_this_packet);
                        k--;
                    }
                }
                if (expected != 0)
                    zero_chunk = false;
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
                transition_to_chunk_bad(accelerate_this_packet);
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
                transition_to_chunk_bad(accelerate_this_packet);
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
                transition_to_chunk_bad(accelerate_this_packet);
                k--;
            }
            break;
        case CHUNK_DATA:
            // Moving through the chunk data
          {
            uint32_t skip_amount = (length-k <= expected) ? length-k : expected;
            if (!discard_mode && (skip_amount > adjusted_target-data_seen))
            { // Do not exceed requested section size (including stretching)
                skip_amount = adjusted_target-data_seen;
            }

            accelerate_this_packet = need_accelerated_blocking(buffer+k, skip_amount) ||
                accelerate_this_packet;

            k += skip_amount - 1;
            if ((expected -= skip_amount) == 0)
            {
                curr_state = CHUNK_DCRLF1;
            }
            if ((data_seen += skip_amount) == adjusted_target)
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
                transition_to_chunk_bad(accelerate_this_packet);
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
            // they will be reassembled after all. This will overrun the adjusted_target making the
            // message section a little bigger than planned. It's not important.
            uint32_t skip_amount = length-k;
            skip_amount = (skip_amount <= adjusted_target-data_seen) ? skip_amount :
                adjusted_target-data_seen;
            accelerate_this_packet = need_accelerated_blocking(buffer+k, skip_amount) ||
                accelerate_this_packet;
            k += skip_amount - 1;
            if ((data_seen += skip_amount) == adjusted_target)
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

    if (data_seen >= flow_target)
    {
        // We passed the flow_target and stretched to the end of the segment
        data_seen = 0;
        num_flush = length;
        return SCAN_FOUND_PIECE;
    }

    octets_seen += length;

    if (accelerate_this_packet || (zero_chunk && data_seen))
        return SCAN_NOT_FOUND_ACCELERATE;

    return SCAN_NOT_FOUND;
}

ScanResult HttpBodyHXCutter::cut(const uint8_t* buffer, uint32_t length,
    HttpInfractions* infractions, HttpEventGen* events, uint32_t flow_target, bool stretch,
    HXBodyState state)
{
    // If the headers included a content length header (expected length >= 0), check it against the
    // actual message body length. Alert if it does not match at the end of the message body or if
    // it overflows during the body (alert once then stop computing).
    if (expected_body_length >= 0)
    {
        if ((total_octets_scanned + length) > expected_body_length)
        {
            *infractions += INF_H2_DATA_OVERRUNS_CL;
            events->create_event(EVENT_H2_DATA_OVERRUNS_CL);
            expected_body_length = STAT_NOT_COMPUTE;
        }
        else if (state != HX_BODY_NOT_COMPLETE and
            ((total_octets_scanned + length) < expected_body_length))
        {
            *infractions += INF_H2_DATA_UNDERRUNS_CL;
            events->create_event(EVENT_H2_DATA_UNDERRUNS_CL);
        }
    }

    if (flow_target == 0)
    {
        num_flush = length;
        total_octets_scanned += length;
        if (state != HX_BODY_NOT_COMPLETE)
            return SCAN_DISCARD;

        return SCAN_DISCARD_PIECE;
    }

    if (state == HX_BODY_NOT_COMPLETE)
    {
        if (octets_seen + length < flow_target)
        {
            // Not enough data yet to create a message section
            octets_seen += length;
            total_octets_scanned += length;
            return need_accelerated_blocking(buffer, length) ?
                SCAN_NOT_FOUND_ACCELERATE : SCAN_NOT_FOUND;
        }
        else
        {
            if (stretch && (octets_seen + length <= flow_target + MAX_SECTION_STRETCH))
                num_flush = length;
            else
                num_flush = flow_target - octets_seen;
            total_octets_scanned += num_flush;
            need_accelerated_blocking(buffer, num_flush);
            return SCAN_FOUND_PIECE;
        }
    }
    else if (state == HX_BODY_LAST_SEG)
    {
        const uint32_t adjusted_target = stretch ? MAX_SECTION_STRETCH + flow_target : flow_target;
        if (octets_seen + length <= adjusted_target)
            num_flush = length;
        else
            num_flush = flow_target - octets_seen;

        total_octets_scanned += num_flush;
        if (num_flush == length)
            return SCAN_FOUND;
        else
            return SCAN_FOUND_PIECE;
    }
    else
    {
        // To end message body when trailers are received or a 0 length data frame with
        // end of stream set is received, a zero-length buffer is sent to flush
        assert(length == 0);
        num_flush = 0;
        return SCAN_FOUND;
    }
}

// This method searches the input stream looking for a script or other dangerous content that
// requires script detection. Exactly what we are looking for is encapsulated in dangerous().
//
// Return value true indicates a match and enables the packet that completes the matching sequence
// to be sent for partial inspection.
//
// Any attempt to optimize this code should be mindful that once you skip any part of the message
// body, dangerous() loses the ability to unzip subsequent data.

bool HttpBodyCutter::need_accelerated_blocking(const uint8_t* data, uint32_t length)
{
    const bool need_accelerated_blocking = accelerated_blocking && dangerous(data, length);
    if (need_accelerated_blocking)
        HttpModule::increment_peg_counts(PEG_SCRIPT_DETECTION);
    return need_accelerated_blocking;
}

bool HttpBodyCutter::find_partial(const uint8_t* input_buf, uint32_t input_length, bool end)
{
    for (uint32_t k = 0; k < input_length; k++)
    {
        // partial_match is persistent, enabling matches that cross data boundaries
        if ((input_buf[k] == match_string[partial_match]) ||
            (input_buf[k] == match_string_upper[partial_match]))
        {
            if (++partial_match == string_length)
            {
                partial_match = 0;
                return true;
            }
        }
        else
        {
            partial_match = 0;
            if ( end )
                return false;
        }
    }
    return false;
}

// Currently we do accelerated blocking when we see a javascript
bool HttpBodyCutter::dangerous(const uint8_t* data, uint32_t length)
{
    const uint8_t* input_buf = data;
    uint32_t input_length = length;
    uint8_t* decomp_output = nullptr;

    // Zipped flows must be decompressed before we can check them. Unzipping for accelerated
    // blocking is completely separate from the unzipping done later in reassemble().
    if ((compression == CMP_GZIP) || (compression == CMP_DEFLATE))
    {
        // Previous decompression failures make it impossible to search for scripts
        if (decompress_failed)
            return true;

        const uint32_t decomp_buffer_size = MAX_OCTETS;
        decomp_output = new uint8_t[decomp_buffer_size];

        compress_stream->next_in = const_cast<Bytef*>(data);
        compress_stream->avail_in = length;
        compress_stream->next_out = decomp_output;
        compress_stream->avail_out = decomp_buffer_size;

        int ret_val = inflate(compress_stream, Z_SYNC_FLUSH);

        // Not going to be subtle about this and try to fix decompression problems. If it doesn't
        // work out we assume it could be dangerous.
        if (((ret_val != Z_OK) && (ret_val != Z_STREAM_END)) || (compress_stream->avail_in > 0))
        {
            decompress_failed = true;
            delete[] decomp_output;
            return true;
        }

        input_buf = decomp_output;
        input_length = decomp_buffer_size - compress_stream->avail_out;
    }

    std::unique_ptr<uint8_t[]> uniq(decomp_output);

    if ( input_length > string_length )
    {
        if ( partial_match and find_partial(input_buf, input_length, true) )
            return true;

        if ( finder->search(input_buf, input_length) >= 0 )
            return true;

        uint32_t delta = input_length - string_length + 1;
        input_buf += delta;
        input_length -= delta;
    }

    if ( find_partial(input_buf, input_length, false) )
        return true;

    return false;
}

