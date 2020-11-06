//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// http2_data_cutter.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_data_cutter.h"

#include "service_inspectors/http_inspect/http_flow_data.h"
#include "service_inspectors/http_inspect/http_stream_splitter.h"

#include "http2_dummy_packet.h"
#include "http2_utils.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

Http2DataCutter::Http2DataCutter(Http2FlowData* _session_data, HttpCommon::SourceId src_id) :
    session_data(_session_data), source_id(src_id)
{ }

void Http2DataCutter::http2_scan(uint32_t length, uint32_t* flush_offset, uint32_t frame_len,
    bool padded, uint32_t& data_offset)
{
    cur_data_offset = data_offset;
    if (frame_bytes_seen == 0)
    {
        data_len = frame_len;
        data_bytes_read = 0;
        frame_bytes_seen = FRAME_HEADER_LENGTH;

        if (padded)
        {
            data_len -= 1;
            frame_bytes_seen += 1;
        }
    }

    uint32_t cur_pos = data_offset;
    const uint32_t missing = data_len - data_bytes_read;
    cur_data = (missing <= (length - cur_pos)) ? missing : (length - cur_pos);
    data_bytes_read += cur_data;
    cur_pos += cur_data;

    frame_bytes_seen += cur_pos - data_offset;
    // FIXIT-L In theory data_offset should be reduced for any bytes not used by HI scan() later.
    // But currently the value is not used in the case where we flush.
    data_offset = cur_pos;
    *flush_offset = cur_pos;
    session_data->scan_remaining_frame_octets[source_id] = frame_len - frame_bytes_seen;
}

StreamSplitter::Status Http2DataCutter::http_scan(const uint8_t* data, uint32_t* flush_offset,
    bool end_stream)
{
    StreamSplitter::Status scan_result = StreamSplitter::SEARCH;

    if (cur_data > 0)
    {
        uint32_t http_flush_offset = 0;
        Http2DummyPacket dummy_pkt;
        dummy_pkt.flow = session_data->flow;
        uint32_t unused = 0;
        scan_result = session_data->hi_ss[source_id]->scan(&dummy_pkt, data + cur_data_offset,
            cur_data, unused, &http_flush_offset);

        if (scan_result == StreamSplitter::FLUSH)
        {
            bytes_sent_http += http_flush_offset;
            const uint32_t unused_input = cur_data - http_flush_offset;
            data_bytes_read -= unused_input;
            *flush_offset -= unused_input;
        }
        else if (scan_result == StreamSplitter::SEARCH)
        {
            bytes_sent_http += cur_data;
        }
        else if (scan_result == StreamSplitter::ABORT)
            // FIXIT-E eventually need to implement continued processing. We cannot abort just
            // because one stream went sideways. A better approach would be to put this one stream
            // into a pass through mode while continuing to process other streams. As long as we
            // can parse the framing and process most streams it is reasonable to continue.
            return StreamSplitter::ABORT;
    }

    if (data_bytes_read == data_len)
    {
        // Done with this frame, cleanup
        session_data->header_octets_seen[source_id] = 0;
        session_data->scan_remaining_frame_octets[source_id] = 0;
        session_data->scan_state[source_id] = SCAN_FRAME_HEADER;
        frame_bytes_seen = 0;

        if (end_stream)
        {
            Http2Stream* const stream = session_data->find_stream(
                session_data->current_stream[source_id]);
            stream->finish_msg_body(source_id, false, !bytes_sent_http);
            // FIXIT-E this flag seems to mean both END_STREAM and the end of this frame
            stream->set_end_stream_on_data_flush(source_id);
            return StreamSplitter::FLUSH;
        }
        else if (scan_result != StreamSplitter::FLUSH)
        {
            assert(scan_result == StreamSplitter::SEARCH);
            scan_result = StreamSplitter::FLUSH;
            if (cur_data > 0)
                session_data->hi_ss[source_id]->init_partial_flush(session_data->flow);
            else
            {
                session_data->payload_discard[source_id] = true;
                assert(!session_data->frame_lengths[source_id].empty());
                session_data->frame_lengths[source_id].pop();
            }
        }
    }

    if (scan_result != StreamSplitter::FLUSH)
        *flush_offset = 0;
    return scan_result;
}

StreamSplitter::Status Http2DataCutter::scan(const uint8_t* data, uint32_t length,
    uint32_t* flush_offset, uint32_t& data_offset, uint32_t frame_len, uint8_t frame_flags)
{
    http2_scan(length, flush_offset, frame_len, frame_flags & PADDED, data_offset);

    session_data->stream_in_hi = session_data->current_stream[source_id];
    StreamSplitter::Status status = http_scan(data, flush_offset, frame_flags & END_STREAM);
    session_data->stream_in_hi = NO_STREAM_ID;

    return status;
}

void Http2DataCutter::reassemble(const uint8_t* data, unsigned len)
{
    session_data->stream_in_hi = session_data->current_stream[source_id];

    cur_data = cur_data_offset = 0;

    unsigned cur_pos = 0;
    while ((cur_pos < len) || (reassemble_state == SEND_EMPTY_DATA))
    {
        switch (reassemble_state)
        {
        case GET_FRAME_HDR:
          {
            const uint32_t missing = FRAME_HEADER_LENGTH - reassemble_hdr_bytes_read;
            const uint32_t cur_frame = ((len - cur_pos) < missing) ? (len - cur_pos) : missing;
            reassemble_hdr_bytes_read += cur_frame;
            cur_pos += cur_frame;

            if (reassemble_hdr_bytes_read == FRAME_HEADER_LENGTH)
            {
                assert(!session_data->frame_lengths[source_id].empty());
                reassemble_data_len = session_data->frame_lengths[source_id].front();
                session_data->frame_lengths[source_id].pop();
                reassemble_frame_flags =
                    get_frame_flags(session_data->lead_frame_header[source_id]);
                cur_data_offset = cur_pos;
                if ((reassemble_frame_flags & PADDED) != 0)
                    reassemble_state = GET_PADDING_LEN;
                else if (reassemble_data_len > 0)
                    reassemble_state = SEND_DATA;
                else if (reassemble_frame_flags & END_STREAM)
                    reassemble_state = SEND_EMPTY_DATA;
                else
                    reassemble_state = DONE;
            }
            break;
          }
        case GET_PADDING_LEN:
          {
            const uint8_t padding_len = *(data + cur_pos);
            reassemble_data_len -= padding_len + 1;
            cur_pos++;
            cur_data_offset++;
            if (reassemble_data_len > 0)
                reassemble_state = SEND_DATA;
            else if (reassemble_frame_flags & END_STREAM)
                reassemble_state = SEND_EMPTY_DATA;
            else
                reassemble_state = DONE;
            break;
          }
        case SEND_EMPTY_DATA:
        case SEND_DATA:
          {
            reassemble_state = SEND_DATA;
            const uint32_t missing = reassemble_data_len - reassemble_data_bytes_read;
            cur_data = ((len - cur_pos) >= missing) ? missing : (len - cur_pos);
            reassemble_data_bytes_read += cur_data;
            cur_pos += cur_data;

            unsigned copied;
            const uint32_t flags = (bytes_sent_http == (cur_data + reassemble_bytes_sent)) ?
                PKT_PDU_TAIL : 0;
            StreamBuffer frame_buf = session_data->hi_ss[source_id]->reassemble(session_data->flow,
                bytes_sent_http, 0, data + cur_data_offset, cur_data,
                flags, copied);
            assert(copied == (unsigned)cur_data);

            if (frame_buf.data != nullptr)
            {
                session_data->frame_data[source_id] = frame_buf.data;
                session_data->frame_data_size[source_id] = frame_buf.length;
                bytes_sent_http = 0;
                reassemble_bytes_sent = 0;
            }
            else
                reassemble_bytes_sent += copied;

            if (reassemble_data_bytes_read == reassemble_data_len)
                reassemble_state = DONE;

            break;
          }
        case DONE:
            assert(false);
            break;
        }
    }

    session_data->stream_in_hi = NO_STREAM_ID;
    return;
}

void Http2DataCutter::reset()
{
    frame_bytes_seen = 0;
    bytes_sent_http = 0;
    reassemble_bytes_sent = 0;
    reassemble_hdr_bytes_read = 0;
    reassemble_data_bytes_read = 0;
    reassemble_state = GET_FRAME_HDR;
}

