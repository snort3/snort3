//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
// http2_frame.h author Katura Harvey <katharve@cisco.com>

#ifndef HTTP2_FRAME_H
#define HTTP2_FRAME_H

#include "protocols/packet.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"

#include "http2_enum.h"

/* This class is called Http2Frame, but an object of this class may not represent exactly one
 * HTTP/2 frame as received on the wire. For HEADERS frames, the Http2Frame object contains the
 * initial HEADERS frame plus any following CONTINUATION frames grouped together. For DATA frames,
 * the Http2Frame object represents approximately 16kb of data to be inspected. This may consist
 * of part of a larger DATA frame cut into 16kb-sized pieces, or several smaller DATA frames
 * aggregated together.
 */

class Http2FlowData;
class Http2Stream;

class Http2Frame
{
public:
    virtual ~Http2Frame() = default;
    static Http2Frame* new_frame(const uint8_t* header_buffer, const uint32_t header_len,
        const uint8_t* data_buffer, const uint32_t data_len, Http2FlowData* session_data,
        HttpCommon::SourceId source_id, Http2Stream* stream);
    virtual bool valid_sequence(Http2Enums::StreamState) { return true; }
    virtual void analyze_http1(snort::Packet*) { }
    virtual void clear(snort::Packet*) { }
    virtual const Field& get_buf(unsigned id);
    virtual bool is_detection_required() const { return true; }
    virtual void update_stream_state() { }
    const uint8_t* get_frame_pdu(uint16_t& length) const;
    virtual const uint8_t* get_frame_data(uint32_t& length) const;
#ifdef REG_TEST
    virtual void print_frame(FILE* output);
#endif

protected:
    Http2Frame(const uint8_t* header_buffer, const uint32_t header_len,
        const uint8_t* data_buffer, const uint32_t data_len, Http2FlowData* session_data,
        HttpCommon::SourceId source_id, Http2Stream* stream);
    uint8_t get_flags();
    uint32_t get_stream_id();
    virtual uint8_t get_flags_mask() const { return 0; }

    Field header;
    Field data;
    Http2FlowData* session_data;
    HttpCommon::SourceId source_id;
    Http2Stream* stream;

    const static uint8_t flags_index = 4;
    const static uint8_t stream_id_index = 5;
    const static uint32_t INVALID_STREAM_ID = 0xFFFFFFFF;
};
#endif
