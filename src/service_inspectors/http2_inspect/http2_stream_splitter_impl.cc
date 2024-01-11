//--------------------------------------------------------------------------
// Copyright (C) 2018-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "http2_stream_splitter.h"

#include <cassert>

#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_flow_data.h"
#include "service_inspectors/http_inspect/http_stream_splitter.h"
#include "service_inspectors/http_inspect/http_test_input.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include "http2_data_cutter.h"
#include "http2_flow_data.h"
#include "http2_utils.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

enum ValidationResult { V_GOOD, V_BAD, V_TBD };

static ValidationResult validate_preface(const uint8_t* data, const uint32_t length,
    const uint32_t octets_seen)
{
    const uint32_t preface_length = 24;

    static const uint8_t connection_prefix[] = { 'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P',
        '/', '2', '.', '0', '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n' };

    assert(octets_seen < preface_length);

    const uint32_t count = (octets_seen + length) < preface_length ? length :
        (preface_length - octets_seen);

    if (memcmp(data, connection_prefix + octets_seen, count))
        return V_BAD;

    if ((octets_seen + length) < preface_length)
        return V_TBD;

    return V_GOOD;
}

void Http2StreamSplitter::data_frame_header_checks(Http2FlowData* session_data,
     HttpCommon::SourceId source_id)
{
    Http2Stream* const stream = session_data->find_stream(session_data->current_stream[source_id]);

    if (!stream || !stream->is_open(source_id))
    {
        if (!(stream && (stream->get_state(source_id) == STREAM_ERROR)))
        {
            *session_data->infractions[source_id] += INF_FRAME_SEQUENCE;
            session_data->events[source_id]->create_event(EVENT_FRAME_SEQUENCE);
            if (stream)
            {
                // FIXIT-E need to do this even if the stream does not exist yet
                stream->set_state(source_id, STREAM_ERROR);
            }
        }
    }
}

StreamSplitter::Status Http2StreamSplitter::non_data_scan(Http2FlowData* session_data,
    uint32_t length, uint32_t* flush_offset, HttpCommon::SourceId source_id, uint8_t type,
    uint8_t frame_flags, uint32_t& data_offset)
{
    // If we don't have the full frame, keep scanning
    if (length - data_offset < session_data->scan_remaining_frame_octets[source_id])
    {
        session_data->scan_remaining_frame_octets[source_id] -= (length - data_offset);
        data_offset = length;
        return StreamSplitter::SEARCH;
    }

    // Have the full frame
    StreamSplitter::Status status = StreamSplitter::FLUSH;
    session_data->continuation_expected[source_id] = false;
    if (((type == FT_HEADERS) || (type == FT_PUSH_PROMISE) || (type == FT_CONTINUATION)) &&
        !(frame_flags & FLAG_END_HEADERS))
    {
        session_data->continuation_expected[source_id] = true;
        status = StreamSplitter::SEARCH;
    }

    data_offset += session_data->scan_remaining_frame_octets[source_id];
    *flush_offset = data_offset;
    session_data->header_octets_seen[source_id] = 0;
    session_data->scan_remaining_frame_octets[source_id] = 0;
    session_data->scan_state[source_id] = SCAN_FRAME_HEADER;
    return status;
}

bool Http2StreamSplitter::read_frame_hdr(Http2FlowData* session_data, const uint8_t* data,
    uint32_t length, HttpCommon::SourceId source_id, uint32_t& data_offset)
{
    // The first nine bytes are the frame header. But all nine might not all be
    // present in the first TCP segment we receive.
    const uint32_t remaining_header = FRAME_HEADER_LENGTH -
        session_data->header_octets_seen[source_id];
    const uint32_t remaining_header_in_data = remaining_header > length - data_offset ?
        length - data_offset : remaining_header;
    memcpy(session_data->scan_frame_header[source_id] +
        session_data->header_octets_seen[source_id], data + data_offset,
        remaining_header_in_data);
    session_data->header_octets_seen[source_id] += remaining_header_in_data;
    data_offset += remaining_header_in_data;

    if (session_data->header_octets_seen[source_id] < FRAME_HEADER_LENGTH)
        return false;

    return true;
}

StreamSplitter::Status Http2StreamSplitter::implement_scan(Http2FlowData* session_data,
    const uint8_t* data, uint32_t length, uint32_t* flush_offset, HttpCommon::SourceId source_id)
{
    if (session_data->preface[source_id])
    {
        // 24-byte preface, not a real frame, no frame header
        // Verify preface is correct, else generate loss of sync event and abort
        switch (validate_preface(data, length, session_data->preface_octets_seen))
        {
        case V_GOOD:
            *flush_offset = 24 - session_data->preface_octets_seen;
            session_data->preface[source_id] = false;
            session_data->payload_discard[source_id] = true;
            return StreamSplitter::FLUSH;
        case V_BAD:
            session_data->events[source_id]->create_event(EVENT_PREFACE_MATCH_FAILURE);
            session_data->events[source_id]->create_event(EVENT_LOSS_OF_SYNC);
            return StreamSplitter::ABORT;
        case V_TBD:
            session_data->preface_octets_seen += length;
            assert(session_data->preface_octets_seen < 24);
            *flush_offset = length;
            session_data->payload_discard[source_id] = true;
            return StreamSplitter::FLUSH;
        }
        assert(false);
    }

    StreamSplitter::Status status = StreamSplitter::SEARCH;
    *flush_offset = 0;
    uint32_t data_offset = 0;

    // Need to process multiple frames in a single scan() if a single TCP segment has multiple
    // header and continuation frames
    while ((status == StreamSplitter::SEARCH) &&
        ((data_offset < length) or (session_data->scan_state[source_id] == SCAN_EMPTY_DATA)))
    {
        switch(session_data->scan_state[source_id])
        {
            case SCAN_FRAME_HEADER:
            {
                // Discard padding that trails previous Data frame
                if (session_data->remaining_data_padding[source_id] > 0)
                {
                    const uint8_t avail =
                        session_data->remaining_data_padding[source_id] <= (length - data_offset) ?
                        session_data->remaining_data_padding[source_id] : (length - data_offset);
                    session_data->remaining_data_padding[source_id] -= avail;
                    assert(session_data->scan_remaining_frame_octets[source_id] >= avail);
                    session_data->scan_remaining_frame_octets[source_id] -= avail;
                    session_data->payload_discard[source_id] = true;
                    *flush_offset = avail;
                    return StreamSplitter::FLUSH;
                }

                if (!read_frame_hdr(session_data, data, length, source_id, data_offset))
                    return StreamSplitter::SEARCH;

                // We have the full frame header, compute some variables
                const uint8_t type = get_frame_type(session_data->scan_frame_header[source_id]);
                const uint32_t old_stream_id = session_data->current_stream[source_id];
                session_data->current_stream[source_id] =
                    get_stream_id_from_header(session_data->scan_frame_header[source_id]);

                if (session_data->continuation_expected[source_id] &&
                    ((type != FT_CONTINUATION) ||
                     (old_stream_id != session_data->current_stream[source_id])))
                {
                    *session_data->infractions[source_id] += INF_MISSING_CONTINUATION;
                    session_data->events[source_id]->create_event(EVENT_MISSING_CONTINUATION);
                    session_data->events[source_id]->create_event(EVENT_LOSS_OF_SYNC);
                    return StreamSplitter::ABORT;
                }

                const uint32_t frame_length = get_frame_length(session_data->
                    scan_frame_header[source_id]);
                session_data->frame_lengths[source_id].push(frame_length);
                const uint8_t frame_flags = get_frame_flags(session_data->
                    scan_frame_header[source_id]);

                uint32_t& accumulated_frame_length = session_data->accumulated_frame_length[source_id];
                if ((type == FT_HEADERS || type == FT_PUSH_PROMISE) && !(frame_flags & FLAG_END_HEADERS))
                    accumulated_frame_length = frame_length + FRAME_HEADER_LENGTH;

                if (type != FT_CONTINUATION)
                {
                    session_data->frame_type[source_id] = type;
                    memcpy(session_data->lead_frame_header[source_id],
                        session_data->scan_frame_header[source_id], FRAME_HEADER_LENGTH);
                }
                else
                {
                    if (!session_data->continuation_expected[source_id])
                    {
                        *session_data->infractions[source_id] += INF_UNEXPECTED_CONTINUATION;
                        session_data->events[source_id]->create_event(EVENT_UNEXPECTED_CONTINUATION);
                        session_data->events[source_id]->create_event(EVENT_LOSS_OF_SYNC);
                        return StreamSplitter::ABORT;
                    }
                    // Do flags check for continuation frame, since it is not saved
                    // as lead frame for later.
                    if ((frame_flags & FLAG_END_HEADERS) != frame_flags)
                    {
                        *session_data->infractions[source_id] += INF_INVALID_FLAG;
                        session_data->events[source_id]->create_event(EVENT_INVALID_FLAG);
                    }
                    accumulated_frame_length += frame_length + FRAME_HEADER_LENGTH;
                }

                if (((type == FT_CONTINUATION) && (accumulated_frame_length > MAX_OCTETS)) ||
                    ((type != FT_DATA) && (frame_length + FRAME_HEADER_LENGTH > MAX_OCTETS)))
                {
                    // FIXIT-E long non-data frames may need to be supported
                    *session_data->infractions[source_id] += INF_NON_DATA_FRAME_TOO_LONG;
                    session_data->events[source_id]->create_event(EVENT_NON_DATA_FRAME_TOO_LONG);
                    session_data->events[source_id]->create_event(EVENT_LOSS_OF_SYNC);
                    return StreamSplitter::ABORT;
                }

                assert(session_data->scan_remaining_frame_octets[source_id] == 0);
                session_data->scan_remaining_frame_octets[source_id] = frame_length;

                if ((frame_flags & FLAG_PADDED) &&
                    (type == FT_DATA || type == FT_HEADERS || type == FT_PUSH_PROMISE))
                {
                    if (frame_length == 0)
                    {
                        *session_data->infractions[source_id] += INF_PADDING_ON_EMPTY_FRAME;
                        session_data->events[source_id]->create_event(
                            EVENT_PADDING_ON_EMPTY_FRAME);
                        session_data->events[source_id]->create_event(EVENT_LOSS_OF_SYNC);
                        return StreamSplitter::ABORT;
                    }
                    session_data->scan_state[source_id] = SCAN_PADDING_LENGTH;
                }
                else
                {
                    session_data->padding_length[source_id] = 0;
                    if (frame_length == 0)
                        session_data->scan_state[source_id] = SCAN_EMPTY_DATA;
                    else
                        session_data->scan_state[source_id] = SCAN_DATA;
                }

                if (type == FT_DATA)
                    data_frame_header_checks(session_data, source_id);

                break;
            }
            case SCAN_PADDING_LENGTH:
                assert(session_data->scan_remaining_frame_octets[source_id] > 0);
                session_data->padding_length[source_id] = *(data + data_offset);
                if (session_data->frame_type[source_id] == FT_DATA)
                {
                    session_data->remaining_data_padding[source_id] =
                        session_data->padding_length[source_id];
                }
                session_data->scan_remaining_frame_octets[source_id] -= 1;
                assert(!session_data->frame_lengths[source_id].empty());
                if (session_data->padding_length[source_id] >
                    session_data->frame_lengths[source_id].back() - 1)
                {
                    *session_data->infractions[source_id] += INF_PADDING_LEN;
                    session_data->events[source_id]->create_event(EVENT_PADDING_LEN);
                    session_data->events[source_id]->create_event(EVENT_LOSS_OF_SYNC);
                    return StreamSplitter::ABORT;
                }
                data_offset++;

                if (session_data->scan_remaining_frame_octets[source_id] == 0)
                {
                    assert(session_data->padding_length[source_id] == 0);
                    session_data->scan_state[source_id] = SCAN_EMPTY_DATA;
                }
                else
                    session_data->scan_state[source_id] = SCAN_DATA;
                break;
            case SCAN_DATA:
            case SCAN_EMPTY_DATA:
            {
                const uint8_t type = get_frame_type(session_data->scan_frame_header[source_id]);
                const uint8_t frame_flags = get_frame_flags(session_data->
                    scan_frame_header[source_id]);
                if (session_data->frame_type[source_id] != FT_DATA)
                {
                    status = non_data_scan(session_data, length, flush_offset, source_id, type,
                        frame_flags, data_offset);
                }
                else
                {
                    status = session_data->data_cutter[source_id].scan(data, length, flush_offset,
                            data_offset, frame_flags);
                }
                assert(status != StreamSplitter::SEARCH or
                    session_data->scan_state[source_id] != SCAN_EMPTY_DATA);
                break;
            }
        }
    }

    return status;
}

const StreamBuffer Http2StreamSplitter::implement_reassemble(Http2FlowData* session_data,
    unsigned total, unsigned offset, const uint8_t* data, unsigned len, uint32_t flags,
    HttpCommon::SourceId source_id)
{
    StreamBuffer frame_buf { nullptr, 0 };

    if ((session_data->running_total[source_id] != offset) ||
        (total != session_data->bytes_scanned[source_id]) ||
        (offset+len > total) ||
        ((flags & PKT_PDU_TAIL) && (offset+len != total)))
    {
         assert(false);
         session_data->abort_flow[source_id] = true;
         return frame_buf;
    }
    session_data->running_total[source_id] += len;

    if (session_data->frame_type[source_id] == FT_DATA)
    {
        if (len != 0)
        {
            session_data->data_cutter[source_id].reassemble(data, len);
        }
    }
    else
    {
        if (offset == 0)
        {
            // This is the first reassemble() for this frame - allocate data buffer
            session_data->frame_data_size[source_id] =
                total - (session_data->frame_lengths[source_id].size() * FRAME_HEADER_LENGTH);
            if (session_data->frame_data_size[source_id] > 0)
                session_data->frame_reassemble[source_id] = new uint8_t[
                    session_data->frame_data_size[source_id]];

            session_data->frame_data_offset[source_id] = 0;
            session_data->remaining_frame_octets[source_id] = 0;
            session_data->remaining_padding_reassemble[source_id] = 0;
            session_data->read_frame_header[source_id] = true;
            session_data->continuation_frame[source_id] = false;
        }

        uint32_t data_offset = 0;
        while (data_offset < len)
        {
            // Skip frame header
            if (session_data->read_frame_header[source_id])
            {

                const uint32_t remaining_frame_header = FRAME_HEADER_LENGTH -
                     session_data->frame_header_offset[source_id];
                const uint32_t octets_to_skip = remaining_frame_header > len - data_offset ?
                    len - data_offset : remaining_frame_header;
                session_data->frame_header_offset[source_id] += octets_to_skip;
                data_offset += octets_to_skip;

                if (session_data->frame_header_offset[source_id] != FRAME_HEADER_LENGTH)
                    break;
                session_data->read_frame_header[source_id] = false;
                session_data->frame_header_offset[source_id] = 0;

                // Just passed a header: parse and update frame variables
                assert(!session_data->frame_lengths[source_id].empty());
                session_data->remaining_frame_octets[source_id] =
                    session_data->frame_lengths[source_id].front();
                session_data->frame_lengths[source_id].pop();

                const uint8_t frame_flags =
                    get_frame_flags(session_data->lead_frame_header[source_id]);
                const uint8_t type = session_data->frame_type[source_id];
                if ((frame_flags & FLAG_PADDED) && !session_data->continuation_frame[source_id] &&
                    (type == FT_HEADERS || type == FT_PUSH_PROMISE))
                    session_data->read_padding_len[source_id] = true;

                if (data_offset == len)
                    break;
            }

            // Read the padding length if necessary
            if (session_data->read_padding_len[source_id])
            {
                session_data->read_padding_len[source_id] = false;
                session_data->remaining_padding_reassemble[source_id] = *(data + data_offset);
                data_offset += 1;
                session_data->remaining_frame_octets[source_id] -= 1;
                // Subtract the padding and padding length from the frame data size
                session_data->frame_data_size[source_id] -=
                    (session_data->remaining_padding_reassemble[source_id] + 1);

                if (data_offset == len)
                    break;
            }

            // Copy data into the frame buffer until we run out of data or reach the end of the
            // current frame's data
            const uint32_t remaining_frame_payload =
                session_data->remaining_frame_octets[source_id] -
                session_data->remaining_padding_reassemble[source_id];
            const uint32_t octets_to_copy = remaining_frame_payload < len - data_offset ?
                remaining_frame_payload : len - data_offset;
            if (octets_to_copy > 0)
            {
                memcpy(session_data->frame_reassemble[source_id] +
                    session_data->frame_data_offset[source_id],
                    data + data_offset, octets_to_copy);
            }
            session_data->frame_data_offset[source_id] += octets_to_copy;
            session_data->remaining_frame_octets[source_id] -= octets_to_copy;
            data_offset += octets_to_copy;

            if (data_offset == len)
                break;

            // Skip over any padding
            const uint32_t padding_bytes_to_skip =
                session_data->remaining_padding_reassemble[source_id] > len - data_offset ?
                len - data_offset : session_data->remaining_padding_reassemble[source_id];
            session_data->remaining_frame_octets[source_id] -= padding_bytes_to_skip;
            session_data->remaining_padding_reassemble[source_id] -= padding_bytes_to_skip;
            data_offset += padding_bytes_to_skip;

            if (data_offset == len)
                break;

            session_data->read_frame_header[source_id] = true;
            session_data->continuation_frame[source_id] = true;
            assert(session_data->remaining_padding_reassemble[source_id] == 0);
        }
        assert(data_offset == len);
    }

    if (flags & PKT_PDU_TAIL)
    {
        if (session_data->frame_type[source_id] != FT_DATA)
        {
            session_data->frame_data[source_id] = session_data->frame_reassemble[source_id];
            session_data->frame_reassemble[source_id] = nullptr;
        }

        if (session_data->frame_type[source_id] == FT_DATA &&
            session_data->frame_data[source_id] == nullptr)
        {
            Http2Stream* const stream =
                session_data->find_stream(session_data->current_stream[source_id]);
            if (stream)
            {
                stream->set_discard(source_id);
                session_data->data_cutter[source_id].discarded_frame_cleanup(stream);
            }
        }
        else
        {
            // Return 0-length non-null buffer to stream which signals detection required,
            // but don't create pkt_data buffer
            frame_buf.data = (const uint8_t*)"";
        }
        session_data->running_total[source_id] = 0;
        session_data->bytes_scanned[source_id] = 0;
    }

    return frame_buf;
}
