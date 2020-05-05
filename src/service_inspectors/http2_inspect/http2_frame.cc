//--------------------------------------------------------------------------
// Copyright (C) 2019-2020 Cisco and/or its affiliates. All rights reserved.
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
// http2_frame.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_frame.h"

#include "http2_data_frame.h"
#include "http2_enum.h"
#include "http2_flow_data.h"
#include "http2_headers_frame.h"
#include "http2_settings_frame.h"
#include "http2_stream.h"
#include "service_inspectors/http_inspect/http_field.h"

using namespace HttpCommon;
using namespace Http2Enums;
using namespace snort;

Http2Frame::Http2Frame(const uint8_t* header_buffer, const int32_t header_len,
    const uint8_t* data_buffer, const int32_t data_len, Http2FlowData* session_data,
    SourceId source_id, Http2Stream* stream_) :  session_data(session_data), source_id(source_id),
    stream(stream_)
{
    if (header_len > 0)
        header.set(header_len, header_buffer, true);
    if (data_len > 0)
        data.set(data_len, data_buffer, true);
}

Http2Frame* Http2Frame::new_frame(const uint8_t* header, const int32_t header_len,
    const uint8_t* data, const int32_t data_len, Http2FlowData* session_data, SourceId source_id,
    Http2Stream* stream)
{
    // FIXIT-E call the appropriate frame subclass constructor based on the type
    switch(session_data->frame_type[source_id])
    {
        case FT_HEADERS:
            return new Http2HeadersFrame(header, header_len, data, data_len, session_data,
                source_id, stream);
        case FT_SETTINGS:
            return new Http2SettingsFrame(header, header_len, data, data_len, session_data,
                source_id, stream);
        case FT_DATA:
            return new Http2DataFrame(header, header_len, data, data_len, session_data, source_id,
                stream);
        default:
            return new Http2Frame(header, header_len, data, data_len, session_data, source_id, stream);
    }
}

const Field& Http2Frame::get_buf(unsigned id)
{
    switch (id)
    {
    case HTTP2_BUFFER_FRAME_HEADER:
        return header;
    case HTTP2_BUFFER_FRAME_DATA:
        return data;
    default:
        return Field::FIELD_NULL;
    }
}

uint8_t Http2Frame::get_flags()
{
    if (header.length() > 0)
        return header.start()[flags_index];
    else
        return 0;
}

uint32_t Http2Frame::get_stream_id()
{
    if (header.length() <= 0)
        return INVALID_STREAM_ID;

    const uint8_t* header_start = header.start();
    return ((header_start[stream_id_index] & 0x7f) << 24) +
        (header_start[stream_id_index + 1] << 16) +
        (header_start[stream_id_index + 2] << 8) +
        header_start[stream_id_index + 3];
}

#ifdef REG_TEST
void Http2Frame::print_frame(FILE* output)
{
    header.print(output, "Frame Header");
    data.print(output, "Frame Data");
}
#endif
