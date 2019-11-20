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
// http2_hpack.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP2_HPACK_H
#define HTTP2_HPACK_H

#include "service_inspectors/http_inspect/http_common.h"

#include "http2_hpack_int_decode.h"
#include "http2_hpack_string_decode.h"
#include "http2_hpack_table.h"

class Http2FlowData;
class Field;
class Http2StartLine;

// This class implements HPACK decompression. One instance is required in each direction for each
// HTTP/2 flow
class Http2HpackDecoder
{
public:
    Http2HpackDecoder() { }
    bool decode_headers(const uint8_t* encoded_headers, const uint32_t encoded_headers_length,
        uint8_t* decoded_headers, uint32_t* decoded_headers_size, Http2StartLine* start_line,
        Http2EventGen* stream_events, Http2Infractions* stream_infractions);
    bool write_decoded_headers(const uint8_t* in_buffer, const uint32_t in_length,
        uint8_t* decoded_header_buffer, uint32_t decoded_header_length, uint32_t &bytes_written);
    bool decode_header_line(const uint8_t* encoded_header_buffer,
        const uint32_t encoded_header_length, uint32_t& bytes_consumed,
        uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
        uint32_t& bytes_written);
    bool decode_literal_header_line(const uint8_t* encoded_header_buffer,
        const uint32_t encoded_header_length, const uint8_t name_index_mask,
        const Http2HpackIntDecode &decode_int, uint32_t &bytes_consumed,
        uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
        uint32_t &bytes_written);
    bool decode_string_literal(const uint8_t* encoded_header_buffer,
        const uint32_t encoded_header_length, bool is_field_name, uint32_t &bytes_consumed,
        uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
        uint32_t &bytes_written);
    bool decode_index(const uint8_t* encoded_header_buffer,
        const uint32_t encoded_header_length, const Http2HpackIntDecode &decode_int,
        const bool decode_full_line, uint32_t &bytes_consumed, uint8_t* decoded_header_buffer,
        const uint32_t decoded_header_length, uint32_t &bytes_written);
    bool handle_dynamic_size_update(const uint8_t* encoded_header_buffer,
        const uint32_t encoded_header_length, const Http2HpackIntDecode &decode_int,
        uint32_t &bytes_consumed, uint32_t &bytes_written);
    bool decode_static_table_index(const uint64_t index, const bool decode_full_line,
        uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
        uint32_t& bytes_written);
    bool decode_dynamic_table_index(const uint64_t index, const bool decode_full_line,
        uint32_t &bytes_consumed, const uint8_t* encoded_header_buffer,
        uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
        uint32_t& bytes_written);
    bool finalize_start_line();
    const Field* get_start_line();
    const Field* get_decoded_headers(const uint8_t* const decoded_headers);

    static const int STATIC_TABLE_MAX_INDEX = 61;

private:
    Http2StartLine* start_line = nullptr;
    uint32_t* decoded_headers_size;
    uint32_t pseudo_headers_fragment_size = 0;
    bool decode_error = false;
    Http2EventGen* events;
    Http2Infractions* infractions;

    static Http2HpackIntDecode decode_int7;
    static Http2HpackIntDecode decode_int6;
    static Http2HpackIntDecode decode_int5;
    static Http2HpackIntDecode decode_int4;
    static Http2HpackStringDecode decode_string;

    static Http2HpackTable table; //static until dynamic table is implemented

    const static uint8_t index_mask = 0x80;
    const static uint8_t literal_index_mask = 0x40;
    const static uint8_t literal_index_name_index_mask = 0x3f;
    const static uint8_t literal_no_index_mask = 0xf0;
    const static uint8_t literal_never_index_pattern = 0x10;
    const static uint8_t literal_no_index_name_index_mask = 0x0f;

};

#endif

