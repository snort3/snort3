//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
// http2_stream_splitter_impl.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "http2_stream_splitter.h"
#include "protocols/packet.h"
#include "http2_flow_data.h"

using namespace snort;
using namespace Http2Enums;

StreamSplitter::Status implement_scan(Http2FlowData* session_data, const uint8_t* data,
    uint32_t length, uint32_t* flush_offset, Http2Enums::SourceId source_id)
{
    if (session_data->preface[source_id])
    {
        // 24-byte preface, not a real frame, no frame header
        *flush_offset = 24;
        session_data->header_coming[source_id] = false;
        session_data->preface[source_id] = false;
    }
    else if (session_data->leftover_data[source_id] > 0)
    {
        // Continuation of ongoing data frame
        session_data->header_coming[source_id] = false;
        *flush_offset = (session_data->leftover_data[source_id] < DATA_SECTION_SIZE) ?
            session_data->leftover_data[source_id] : DATA_SECTION_SIZE;
        session_data->leftover_data[source_id] -= *flush_offset;
    }
    else
    {
        // frame with header
        if (session_data->frame_header[source_id] == nullptr)
        {
            session_data->header_coming[source_id] = true;
            session_data->frame_header[source_id] = new uint8_t[FRAME_HEADER_LENGTH];
            session_data->octets_seen[source_id] = 0;
        }

        // The first nine bytes are the frame header. But all nine might not all be present in the
        // first TCP segment we receive.
        for (uint32_t k = 0; (k < length) && (session_data->octets_seen[source_id] <
            FRAME_HEADER_LENGTH); k++, session_data->octets_seen[source_id]++)
        {
            session_data->frame_header[source_id][session_data->octets_seen[source_id]] = data[k];
        }
        if (session_data->octets_seen[source_id] < FRAME_HEADER_LENGTH)
            return StreamSplitter::SEARCH;

        uint32_t const frame_length = (session_data->frame_header[source_id][0] << 16) +
                                      (session_data->frame_header[source_id][1] << 8) +
                                       session_data->frame_header[source_id][2];
        if ((session_data->frame_header[source_id][3] == FT_DATA) &&
            (frame_length > DATA_SECTION_SIZE))
        {
            // Long data frame is cut into pieces
            *flush_offset = DATA_SECTION_SIZE + FRAME_HEADER_LENGTH;
            session_data->leftover_data[source_id] = frame_length - DATA_SECTION_SIZE;
        }
        else if (frame_length + FRAME_HEADER_LENGTH > MAX_OCTETS)
        {
            // FIXIT-M long non-data frame needs to be supported
            return StreamSplitter::ABORT;
        }
        else
        {
            // Normal case
            *flush_offset = frame_length + FRAME_HEADER_LENGTH;
        }
    }
    return StreamSplitter::FLUSH;
}

const StreamBuffer implement_reassemble(Http2FlowData* session_data, unsigned total,
    unsigned offset, const uint8_t* data, unsigned len, uint32_t flags, unsigned& copied,
    Http2Enums::SourceId source_id)
{
    assert(offset+len <= total);
    assert(total >= FRAME_HEADER_LENGTH);
    assert(total <= Http2Enums::MAX_OCTETS);

    StreamBuffer frame_buf { nullptr, 0 };

    if (offset == 0)
    {
        session_data->frame[source_id] = new uint8_t[total];
        session_data->frame_size[source_id] = total;
    }
    assert(session_data->frame_size[source_id] == total);

    memcpy(session_data->frame[source_id]+offset, data, len);
    copied = len;
    if (flags & PKT_PDU_TAIL)
    {
        assert(offset+len == total);
        if (!session_data->header_coming[source_id])
        {
            session_data->frame_data[source_id] = session_data->frame[source_id];
            frame_buf.data = session_data->frame_data[source_id];
            session_data->frame_data_size[source_id] = session_data->frame_size[source_id];
            frame_buf.length = session_data->frame_data_size[source_id];
        }
        else if (session_data->frame_size[source_id] == FRAME_HEADER_LENGTH)
        {
            session_data->frame_data[source_id] = nullptr;
            session_data->frame_data_size[source_id] = 0;
            // Don't send empty frame body to detection, use header so there is something
            frame_buf.data = session_data->frame[source_id];
            frame_buf.length = session_data->frame_size[source_id];
        }
        else
        {
            // Adjust for frame header
            session_data->frame_data[source_id] =
                session_data->frame[source_id] + FRAME_HEADER_LENGTH;
            frame_buf.data = session_data->frame_data[source_id];
            session_data->frame_data_size[source_id] =
                session_data->frame_size[source_id] - FRAME_HEADER_LENGTH;
            frame_buf.length = session_data->frame_data_size[source_id];
        }
    }
    return frame_buf;
}

