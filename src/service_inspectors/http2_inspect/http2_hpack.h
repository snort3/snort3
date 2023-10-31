//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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
#include "utils/event_gen.h"
#include "utils/infractions.h"

#include "http2_hpack_int_decode.h"
#include "http2_hpack_string_decode.h"
#include "http2_hpack_table.h"

class Field;
class Http2FlowData;
class Http2StartLine;

using Http2Infractions = Infractions<Http2Enums::INF__MAX_VALUE, Http2Enums::INF__NONE>;
using Http2EventGen = EventGen<Http2Enums::EVENT__MAX_VALUE, Http2Enums::EVENT__NONE,
    Http2Enums::HTTP2_GID>;

// This class implements HPACK decompression. One instance is required in each direction for each
// HTTP/2 flow
class Http2HpackDecoder
{
public:
    Http2HpackDecoder(Http2FlowData* flow_data, HttpCommon::SourceId src_id,
        Http2EventGen* const _events, Http2Infractions* const _infractions) :
        session_data(flow_data), events(_events), infractions(_infractions), source_id(src_id),
        decode_table(flow_data) { }
    bool decode_headers(const uint8_t* encoded_headers, const uint32_t encoded_headers_length,
         Http2StartLine* start_line, bool trailers);
    bool write_decoded_headers(const uint8_t* in_buffer, const uint32_t in_length,
        uint8_t* decoded_header_buffer, uint32_t decoded_header_length, uint32_t& bytes_written);
    bool decode_header_line(const uint8_t* encoded_header_buffer,
        const uint32_t encoded_header_length, uint32_t& bytes_consumed,
        uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
        uint32_t& bytes_written);
    bool handle_dynamic_size_update(const uint8_t* encoded_header_buffer,
        const uint32_t encoded_header_length, uint32_t& bytes_consumed);
    const HpackTableEntry* get_hpack_table_entry(const uint8_t* encoded_header_buffer,
        const uint32_t encoded_header_length, const Http2HpackIntDecode& decode_int,
        uint32_t& bytes_consumed, uint64_t &index);
    bool write_header_part(const Field& header, const uint8_t* suffix, uint32_t suffix_length,
        uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
        uint32_t& bytes_written);
    bool decode_indexed_name(const uint8_t* encoded_header_buffer,
        const uint32_t encoded_header_length, const Http2HpackIntDecode& decode_int,
        uint32_t& bytes_consumed, uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
        uint32_t& bytes_written, Field& name, bool with_indexing);
    bool decode_literal_header_line(const uint8_t* encoded_header_buffer,
        const uint32_t encoded_header_length, const uint8_t name_index_mask,
        const Http2HpackIntDecode& decode_int, bool with_indexing, uint32_t& bytes_consumed,
        uint8_t* decoded_header_buffer, const uint32_t decoded_header_length, uint32_t& bytes_written,
        Field& name, Field& value);
    bool decode_indexed_header(const uint8_t* encoded_header_buffer,
        const uint32_t encoded_header_length, const Http2HpackIntDecode& decode_int,
        uint32_t &bytes_consumed, uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
        uint32_t& bytes_written, Field& name, Field& value);
    bool decode_string_literal(const uint8_t* encoded_header_buffer,
        const uint32_t encoded_header_length, uint32_t& bytes_consumed,
        uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
        uint32_t& bytes_written, Field& field);

    bool finalize_start_line();
    void set_decoded_headers(Field&);
    bool are_pseudo_headers_allowed() { return pseudo_headers_allowed; }
    void settings_table_size_update(const uint32_t size);
    void cleanup();

private:
    Http2StartLine* start_line = nullptr;
    bool pseudo_headers_allowed = false;
    uint8_t* decoded_headers = nullptr; // working buffer to store decoded headers
    Http2FlowData* session_data;
    Http2EventGen* const events;
    Http2Infractions* const infractions;
    uint32_t decoded_headers_size = 0;
    const HttpCommon::SourceId source_id;

    static Http2HpackIntDecode decode_int7;
    static Http2HpackIntDecode decode_int6;
    static Http2HpackIntDecode decode_int5;
    static Http2HpackIntDecode decode_int4;
    static Http2HpackStringDecode decode_string;

    HpackIndexTable decode_table;
    bool table_size_update_allowed = true;
    uint8_t num_table_size_updates = 0;
    bool is_trailers = false;
    bool expect_table_size_update = false;
    uint32_t min_settings_table_size_received = UINT32_MAX;
};

#endif

