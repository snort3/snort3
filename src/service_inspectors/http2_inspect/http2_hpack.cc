//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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
// http2_hpack.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_hpack.h"

#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include "http2_enum.h"
#include "http2_start_line.h"

using namespace HttpCommon;
using namespace Http2Enums;

Http2HpackIntDecode Http2HpackDecoder::decode_int7(7);
Http2HpackIntDecode Http2HpackDecoder::decode_int6(6);
Http2HpackIntDecode Http2HpackDecoder::decode_int5(5);
Http2HpackIntDecode Http2HpackDecoder::decode_int4(4);
Http2HpackStringDecode Http2HpackDecoder::decode_string;
Http2HpackTable Http2HpackDecoder::table;

bool Http2HpackDecoder::write_decoded_headers(const uint8_t* in_buffer, const uint32_t in_length,
    uint8_t* decoded_header_buffer, uint32_t decoded_header_length, uint32_t &bytes_written)
{
    bool ret = true;
    uint32_t length = in_length;
    bytes_written = 0;

    if (in_length > decoded_header_length)
    {
        length = decoded_header_length;
        *infractions += INF_DECODED_HEADER_BUFF_OUT_OF_SPACE;
        events->create_event(EVENT_MISFORMATTED_HTTP2);
        ret = false;
    }

    memcpy((void*)decoded_header_buffer, (void*) in_buffer, length);
    bytes_written = length;
    return ret;
}

bool Http2HpackDecoder::decode_string_literal(const uint8_t* encoded_header_buffer,
    const uint32_t encoded_header_length, bool is_field_name, uint32_t &bytes_consumed,
    uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
    uint32_t &bytes_written)
{
    uint32_t decoded_bytes_written;
    uint32_t encoded_bytes_consumed;
    uint32_t encoded_header_offset = 0;
    bytes_written = 0;
    bytes_consumed = 0;

    if (is_field_name)
    {
        // skip over parsed pattern and zeroed index
        encoded_header_offset++;
        bytes_consumed++;
    }

    if (!decode_string.translate(encoded_header_buffer + encoded_header_offset,
        encoded_header_length - encoded_header_offset, encoded_bytes_consumed,
        decoded_header_buffer, decoded_header_length, decoded_bytes_written,
        events, infractions))
    {
        return false;
    }

    bytes_consumed += encoded_bytes_consumed;
    bytes_written += decoded_bytes_written;

    if (is_field_name)
    {
        if (!write_decoded_headers((const uint8_t*)": ", 2,
                decoded_header_buffer + bytes_written, decoded_header_length -
                bytes_written, decoded_bytes_written))
            return false;
    }
    else
    {
        if (!write_decoded_headers((const uint8_t*)"\r\n", 2,
                decoded_header_buffer + bytes_written, decoded_header_length -
                bytes_written, decoded_bytes_written))
            return false;
    }

    bytes_written += decoded_bytes_written;

    return true;
}

bool Http2HpackDecoder::decode_static_table_index(const uint64_t index, const bool decode_full_line,
    uint8_t* decoded_header_buffer, const uint32_t decoded_header_length, uint32_t& bytes_written)
{
    uint32_t local_bytes_written = 0;
    const Http2HpackTable::TableEntry* const entry = table.lookup(index);
    bytes_written = 0;

    // Index should never be 0 - zeroed index means string literal
    assert(index > 0);

    // If this is a pseudo-header, pass it to the start line
    if (index < PSEUDO_HEADER_MAX_INDEX)
    {
        start_line->process_pseudo_header_name(index);
    }

    // If this is a regular header, write header name + ': ' to decoded headers
    else
    {
        if (!start_line->is_finalized())
        {
            if (!finalize_start_line())
                return false;
        }

        if (!write_decoded_headers((const uint8_t*) entry->name,
                strlen(entry->name), decoded_header_buffer,
                decoded_header_length, local_bytes_written))
            return false;
        bytes_written += local_bytes_written;
        if (!write_decoded_headers((const uint8_t*)": ", 2,
                decoded_header_buffer + bytes_written,
                decoded_header_length - bytes_written,
                local_bytes_written))
            return false;
        bytes_written += local_bytes_written;
    }

    if (decode_full_line)
    {
        if (strlen(entry->value) == 0)
        {
            *infractions += INF_LOOKUP_EMPTY_VALUE;
            events->create_event(EVENT_MISFORMATTED_HTTP2);
            return false;
        }

        if (index < PSEUDO_HEADER_MAX_INDEX)
        {
            start_line->process_pseudo_header_value(
                (const uint8_t*)entry->value, strlen(entry->value));
        }
        else
        {
            if (!write_decoded_headers((const uint8_t*)entry->value,
                    strlen(entry->value), decoded_header_buffer + bytes_written,
                    decoded_header_length - bytes_written, local_bytes_written))
                return false;
            bytes_written += local_bytes_written;
            if (!write_decoded_headers((const uint8_t*)"\r\n", 2,
                    decoded_header_buffer + bytes_written, decoded_header_length -
                    bytes_written, local_bytes_written))
                return false;
            bytes_written += local_bytes_written;
        }
    }

    return true;
}

// FIXIT-H Implement dynamic table. Currently copies encoded index to decoded headers
bool Http2HpackDecoder::decode_dynamic_table_index(const uint64_t index,
    const bool decode_full_line, uint32_t &bytes_consumed, const uint8_t* encoded_header_buffer,
    uint8_t* decoded_header_buffer, const uint32_t decoded_header_length, uint32_t& bytes_written)
{
    UNUSED(index);
    UNUSED(decode_full_line);

    //FIXIT-H finalize start_line only for regular headers
    if (!start_line->is_finalized())
    {
        if (!finalize_start_line())
            return false;
    }

    if(!write_decoded_headers(encoded_header_buffer,
            bytes_consumed, decoded_header_buffer + bytes_written, decoded_header_length,
            bytes_written))
        return false;
    return true;

}

// FIXIT-H Will be incrementally updated to actually decode indexes. For now just copies encoded
// index directly to decoded_header_buffer
bool Http2HpackDecoder::decode_index(const uint8_t* encoded_header_buffer,
    const uint32_t encoded_header_length, const Http2HpackIntDecode &decode_int,
    const bool decode_full_line, uint32_t &bytes_consumed, uint8_t* decoded_header_buffer,
    const uint32_t decoded_header_length, uint32_t &bytes_written)
{
    uint64_t index;
    bytes_written = 0;
    bytes_consumed = 0;

    if (!decode_int.translate(encoded_header_buffer, encoded_header_length,
        bytes_consumed, index, events, infractions))
    {
        return false;
    }

    if (index <= STATIC_TABLE_MAX_INDEX)
        return decode_static_table_index(index, decode_full_line,
            decoded_header_buffer, decoded_header_length, bytes_written);
    else
        return decode_dynamic_table_index(index, decode_full_line,
            bytes_consumed, encoded_header_buffer, decoded_header_buffer,
            decoded_header_length, bytes_written);
}

bool Http2HpackDecoder::decode_literal_header_line(const uint8_t* encoded_header_buffer,
    const uint32_t encoded_header_length, const uint8_t name_index_mask,
    const Http2HpackIntDecode &decode_int, uint32_t &bytes_consumed,
    uint8_t* decoded_header_buffer, const uint32_t decoded_header_length, uint32_t &bytes_written)
{
    bytes_written = 0;
    bytes_consumed = 0;
    uint32_t partial_bytes_consumed;
    uint32_t partial_bytes_written;
 
    // indexed field name
    if (encoded_header_buffer[0] & name_index_mask)
    {
        if (!Http2HpackDecoder::decode_index(encoded_header_buffer,
                encoded_header_length, decode_int, false, partial_bytes_consumed,
                decoded_header_buffer, decoded_header_length, partial_bytes_written))
        {
            bytes_written += partial_bytes_written;
            return false;
        }
    }
    // literal field name
    else
    {
        if (!Http2HpackDecoder::decode_string_literal(encoded_header_buffer,
                encoded_header_length, true,
                partial_bytes_consumed, decoded_header_buffer, decoded_header_length,
                partial_bytes_written))
        {
            bytes_written += partial_bytes_written;
            return false;
        }
        // If this was a pseudo-header value, give it to the start-line.
        if (start_line->is_pseudo_name(
                (const char*) decoded_header_buffer))
        {
            // don't include the ': ' that was written following the header name
            start_line->process_pseudo_header_name(
                decoded_header_buffer, partial_bytes_written - 2);
        }
        // If not a pseudo-header value, keep it in the decoded headers
        else
        {
            if (!start_line->is_finalized())
            {
                if (!finalize_start_line())
                    return false;
            }
        }
    }
    bytes_written += partial_bytes_written;
    bytes_consumed += partial_bytes_consumed;

    // value is always literal
    if (!Http2HpackDecoder::decode_string_literal(encoded_header_buffer +
            partial_bytes_consumed, encoded_header_length - partial_bytes_consumed,
            false, partial_bytes_consumed,
            decoded_header_buffer + bytes_written, decoded_header_length -
            bytes_written, partial_bytes_written))
    {
        bytes_written += partial_bytes_written;
        return false;
    }

    // If this was a pseudo-header value, give it to the start-line.
    if (start_line->is_pseudo_value())
    {
        // Subtract 2 from the length to remove the trailing CRLF before passing to the start line
        start_line->process_pseudo_header_value(
            decoded_header_buffer + bytes_written, partial_bytes_written - 2);
    }
    bytes_written += partial_bytes_written;
    bytes_consumed += partial_bytes_consumed;

    return true;
}

// FIXIT-M Will be updated to actually update dynamic table size. For now just skips over
bool Http2HpackDecoder::handle_dynamic_size_update(const uint8_t* encoded_header_buffer,
    const uint32_t encoded_header_length, const Http2HpackIntDecode &decode_int,
    uint32_t &bytes_consumed, uint32_t &bytes_written)
{
    uint64_t decoded_int;
    uint32_t encoded_bytes_consumed;
    bytes_consumed = 0;
    bytes_written = 0;

    if (!decode_int.translate(encoded_header_buffer, encoded_header_length,
        encoded_bytes_consumed, decoded_int, events, infractions))
    {
        return false;
    }
#ifdef REG_TEST
    //FIXIT-M remove when dynamic size updates are handled
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2))
    {
            fprintf(HttpTestManager::get_output_file(),
                "Skipping HPACK dynamic size update: %lu\n", decoded_int);
    }
#endif
    bytes_consumed += encoded_bytes_consumed;

    return true;
}

bool Http2HpackDecoder::decode_header_line(const uint8_t* encoded_header_buffer,
    const uint32_t encoded_header_length, uint32_t& bytes_consumed, uint8_t* decoded_header_buffer,
    const uint32_t decoded_header_length, uint32_t& bytes_written)
{
    // indexed header representation
    if (encoded_header_buffer[0] & index_mask)
        return decode_index(encoded_header_buffer,
            encoded_header_length, decode_int7, true, bytes_consumed,
            decoded_header_buffer, decoded_header_length, bytes_written);

    // literal header representation to be added to dynamic table
    else if (encoded_header_buffer[0] & literal_index_mask)
        return decode_literal_header_line(
            encoded_header_buffer, encoded_header_length, literal_index_name_index_mask,
            decode_int6, bytes_consumed, decoded_header_buffer,
            decoded_header_length, bytes_written);

    // literal header field representation not to be added to dynamic table
    // Note that this includes two representation types from the RFC - literal without index and
    // literal never index. From a decoding standpoint these are identical.
    else if ((encoded_header_buffer[0] & literal_no_index_mask) == 0 or
            (encoded_header_buffer[0] & literal_no_index_mask) == literal_never_index_pattern)
        return decode_literal_header_line(
            encoded_header_buffer, encoded_header_length, literal_no_index_name_index_mask,
            decode_int4, bytes_consumed, decoded_header_buffer,
            decoded_header_length, bytes_written);
    else
        // FIXIT-M dynamic table size update not yet supported, just skip
        return handle_dynamic_size_update(encoded_header_buffer,
            encoded_header_length, decode_int5, bytes_consumed, bytes_written);
}

// FIXIT-H This will eventually be the decoded header buffer. String literals and static table
// indexes are decoded. Dynamic table indexes are not yet decoded. Both the start-line and
// http2_decoded_header need to be sent to NHI
bool Http2HpackDecoder::decode_headers(const uint8_t* encoded_headers,
    const uint32_t encoded_headers_length, uint8_t* decoded_headers, uint32_t* decoded_headers_len,
    Http2StartLine *start_line_generator, Http2EventGen* stream_events,
    Http2Infractions* stream_infractions)
{
    uint32_t total_bytes_consumed = 0;
    uint32_t line_bytes_consumed = 0;
    uint32_t line_bytes_written = 0;
    bool success = true;
    start_line = start_line_generator;
    decoded_headers_size = decoded_headers_len;
    events = stream_events;
    infractions = stream_infractions;
    pseudo_headers_fragment_size = 0;

    while (success and total_bytes_consumed < encoded_headers_length)
    {
        success = decode_header_line(encoded_headers + total_bytes_consumed,
            encoded_headers_length - total_bytes_consumed, line_bytes_consumed,
            decoded_headers + *decoded_headers_size, MAX_OCTETS - *decoded_headers_size,
            line_bytes_written);
        total_bytes_consumed  += line_bytes_consumed;
        *decoded_headers_size += line_bytes_written;
    }

    // If there were only pseudo-headers, finalize never got called, so create the start-line
    if (!start_line->is_finalized())
    {
        success &= finalize_start_line();
    }

    // write the last CRLF to end the header
    if (success)
    {
        success = write_decoded_headers((const uint8_t*)"\r\n", 2, decoded_headers +
            *decoded_headers_size, MAX_OCTETS - *decoded_headers_size, line_bytes_written);
        *decoded_headers_size += line_bytes_written;
    }
    else
        decode_error = true;
    return success;
}

bool Http2HpackDecoder::finalize_start_line()//const uint32_t decoded_headers_size)
{
    // Save the current position in the decoded buffer so we can set the pointer to the start
    // of the regular headers
    pseudo_headers_fragment_size = *decoded_headers_size;

    return start_line->finalize();
}

const Field* Http2HpackDecoder::get_start_line()
{
    return start_line->get_start_line();
}

const Field* Http2HpackDecoder::get_decoded_headers(const uint8_t* const decoded_headers)
{
    if (decode_error)
        return new Field(STAT_NO_SOURCE);
    else
        return new Field(*decoded_headers_size - pseudo_headers_fragment_size, decoded_headers +
            pseudo_headers_fragment_size, false);
}
