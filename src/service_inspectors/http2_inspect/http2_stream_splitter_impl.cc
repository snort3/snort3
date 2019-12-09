//--------------------------------------------------------------------------
// Copyright (C) 2018-2019 Cisco and/or its affiliates. All rights reserved.
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
#include "service_inspectors/http_inspect/http_test_input.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include "http2_flow_data.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

static uint32_t get_frame_length(const uint8_t* frame_buffer)
{
    return (frame_buffer[0] << 16) + (frame_buffer[1] << 8) + frame_buffer[2];
}

static uint8_t get_frame_type(const uint8_t* frame_buffer)
{
    const uint8_t frame_type_index = 3;
    if (frame_buffer)
        return frame_buffer[frame_type_index];
    // If there was no frame header, this must be a piece of a long data frame
    else
       return FT_DATA;
}

static uint8_t get_frame_flags(const uint8_t* frame_buffer)
{
    const uint8_t frame_flags_index = 4;
    if (frame_buffer)
        return frame_buffer[frame_flags_index];
    else
        return NO_HEADER;
}

StreamSplitter::Status implement_scan(Http2FlowData* session_data, const uint8_t* data,
    uint32_t length, uint32_t* flush_offset, HttpCommon::SourceId source_id)
{
    StreamSplitter::Status status = StreamSplitter::FLUSH;
    if (session_data->preface[source_id])
    {
        // 24-byte preface, not a real frame, no frame header
        // Verify preface is correct, else generate loss of sync event and abort
        switch (validate_preface(data, length, session_data->scan_octets_seen[source_id]))
        {
            case V_GOOD:
                break;
            case V_BAD:
                session_data->events[source_id]->create_event(EVENT_PREFACE_MATCH_FAILURE);
                return StreamSplitter::ABORT;
            case V_TBD:
                session_data->scan_octets_seen[source_id] += length;
                return StreamSplitter::SEARCH;
        }

        *flush_offset = 24 - session_data->scan_octets_seen[source_id];
        session_data->preface[source_id] = false;
        session_data->payload_discard[source_id] = true;
        session_data->scan_octets_seen[source_id] = 0;
    }
    //FIXIT-M This should get split points from NHI
    else if (session_data->leftover_data[source_id] > 0)
    {
        // Continuation of ongoing data frame
        session_data->num_frame_headers[source_id] = 0;
 
        // If this is a new frame section, update next frame section length
        if (session_data->scan_remaining_frame_octets[source_id] == 0)
        {
            if (session_data->leftover_data[source_id] > DATA_SECTION_SIZE)
                session_data->scan_remaining_frame_octets[source_id] = DATA_SECTION_SIZE;
            else
                 session_data->scan_remaining_frame_octets[source_id] =
                     session_data->leftover_data[source_id];
            session_data->total_bytes_in_split[source_id] = 0;
        }

        // Don't have full frame section, keep scanning
        if (session_data->scan_remaining_frame_octets[source_id] > length)
        {
            session_data->scan_remaining_frame_octets[source_id] -= length;
            session_data->total_bytes_in_split[source_id] += length;
            return status = StreamSplitter::SEARCH;
        } 

        // Have full frame section, flush and update leftover
        session_data->total_bytes_in_split[source_id] +=
            session_data->scan_remaining_frame_octets[source_id];
        *flush_offset = session_data->scan_remaining_frame_octets[source_id];
        session_data->leftover_data[source_id] -=
            session_data->total_bytes_in_split[source_id];
        session_data->octets_before_first_header[source_id] =
            session_data->total_bytes_in_split[source_id];
        session_data->scan_remaining_frame_octets[source_id] = 0;
    }
    else
    {
        // Frame with header
        *flush_offset = 0;
        uint32_t data_offset = 0;
        session_data->octets_before_first_header[source_id] = 0;
        // If there is a header frame followed by a continuation frame in the same tcp segment,
        // need to process multiple frames in a single scan
        do
        {
            // Scanning a new frame
            if (session_data->scan_octets_seen[source_id] == 0)
                session_data->num_frame_headers[source_id] += 1;

            // The first nine bytes are the frame header. But all nine might not all be present in
            // the first TCP segment we receive.
            uint32_t remaining_header = FRAME_HEADER_LENGTH -
                session_data->scan_octets_seen[source_id];
            uint32_t remaining_header_in_data = remaining_header > length - data_offset ?
                length - data_offset : remaining_header;
            memcpy(session_data->scan_frame_header[source_id] +
                session_data->scan_octets_seen[source_id], data + data_offset,
                remaining_header_in_data);
            session_data->scan_octets_seen[source_id] += remaining_header_in_data;
            data_offset += remaining_header_in_data;

            if (session_data->scan_octets_seen[source_id] < FRAME_HEADER_LENGTH)
            {
                status = StreamSplitter::SEARCH;
                break;
            }

            // We have the full frame header, compute some variables
            const uint32_t frame_length = get_frame_length(session_data->
                scan_frame_header[source_id]);
            uint8_t type = get_frame_type(session_data->scan_frame_header[source_id]);

            // Compute frame section length once per frame
            if (session_data->scan_remaining_frame_octets[source_id] == 0)
            {
                if (session_data->continuation_expected[source_id] && type != FT_CONTINUATION)
                {
                    *session_data->infractions[source_id] += INF_MISSING_CONTINUATION;
                    session_data->events[source_id]->create_event(EVENT_MISSING_CONTINUATION);
                    status = StreamSplitter::ABORT;
                    break;
                }
                if ((type == FT_DATA) && (frame_length > DATA_SECTION_SIZE))
                {
                    // Break up long data frames into pieces for detection
                    session_data->scan_remaining_frame_octets[source_id] = DATA_SECTION_SIZE;
                    session_data->total_bytes_in_split[source_id] = DATA_SECTION_SIZE +
                        FRAME_HEADER_LENGTH;
                }
                else if (frame_length + FRAME_HEADER_LENGTH > MAX_OCTETS)
                {
                    // FIXIT-M long non-data frame needs to be supported
                    status = StreamSplitter::ABORT;
                    break;
                }
                else
                {
                    session_data->scan_remaining_frame_octets[source_id] = frame_length;
                    session_data->total_bytes_in_split[source_id] += FRAME_HEADER_LENGTH +
                        frame_length;
                }
            }

            // If we don't have the full frame, keep scanning
            if (length - data_offset < session_data->scan_remaining_frame_octets[source_id])
            {
                session_data->scan_remaining_frame_octets[source_id] -= (length - data_offset);
                status = StreamSplitter::SEARCH;
                break;
            }

            // Have the full frame
            uint8_t frame_flags = get_frame_flags(session_data->scan_frame_header[source_id]);
            switch(type)
            {
                case FT_HEADERS:
                    if (!(frame_flags & END_HEADERS))
                    {
                        session_data->continuation_expected[source_id] = true;
                        status = StreamSplitter::SEARCH;
                    }
                    break;
                case FT_CONTINUATION:
                    if (session_data->continuation_expected[source_id])
                    {
                        if (!(frame_flags & END_HEADERS))
                            status = StreamSplitter::SEARCH;
                        else
                        {
                            // continuation frame ending headers
                            status = StreamSplitter::FLUSH;
                            session_data->continuation_expected[source_id] = false;
                        }
                    }
                    else
                    {
                        // FIXIT-M CONTINUATION frames can also follow PUSH_PROMISE frames, which
                        // are not currently supported
                        *session_data->infractions[source_id] += INF_UNEXPECTED_CONTINUATION;
                        session_data->events[source_id]->create_event(
                            EVENT_UNEXPECTED_CONTINUATION);
                        status = StreamSplitter::ABORT;
                    }
                    break;
                case FT_DATA:
                    session_data->leftover_data[source_id] = frame_length -
                        (session_data->total_bytes_in_split[source_id] - FRAME_HEADER_LENGTH);
                    break;
            }

            data_offset += session_data->scan_remaining_frame_octets[source_id];
            *flush_offset = data_offset;
            session_data->scan_octets_seen[source_id] = 0;
            session_data->scan_remaining_frame_octets[source_id] = 0;

        } while (status == StreamSplitter::SEARCH && data_offset < length);
    }
    return status;
}

// FIXIT-M If there are any errors in header decoding, this currently tells stream not to send 
// headers to detection. This behavior may need to be changed.
const StreamBuffer implement_reassemble(Http2FlowData* session_data, unsigned total,
    unsigned offset, const uint8_t* data, unsigned len, uint32_t flags,
    HttpCommon::SourceId source_id)
{
    assert(offset+len <= total);
    assert(total >= FRAME_HEADER_LENGTH);
    assert(total <= MAX_OCTETS);
    assert(total == session_data->total_bytes_in_split[source_id]);

    StreamBuffer frame_buf { nullptr, 0 };

    uint32_t data_offset = 0;

    if (offset == 0)
    {
        // This is the first reassemble() for this frame and we need to allocate some buffers
        session_data->frame_header_size[source_id] = FRAME_HEADER_LENGTH *
            session_data->num_frame_headers[source_id];
        if (session_data->frame_header_size[source_id] > 0)
            session_data->frame_header[source_id] = new uint8_t[
                session_data->frame_header_size[source_id]];

        session_data->frame_data_size[source_id]= total -
            session_data->frame_header_size[source_id];
        if (session_data->frame_data_size[source_id] > 0)
            session_data->frame_data[source_id] = new uint8_t[
                session_data->frame_data_size[source_id]];

        session_data->frame_header_offset[source_id] = 0;
        session_data->frame_data_offset[source_id] = 0;
        session_data->remaining_frame_octets[source_id] =
            session_data->octets_before_first_header[source_id];
        session_data->padding_octets_in_frame[source_id] = 0;
    }

    do
    {
        uint32_t octets_to_copy;

        // Read the padding length if necessary
        if (session_data->get_padding_len[source_id])
        {
            session_data->get_padding_len[source_id] = false;
            session_data->padding_octets_in_frame[source_id] = *(data + data_offset);
            data_offset += 1;
            session_data->remaining_frame_octets[source_id] -= 1;
            // Subtract the padding and padding length from the frame data size
            session_data->frame_data_size[source_id] -=
                (session_data->padding_octets_in_frame[source_id] + 1);
        }

        // Copy data into the frame buffer until we run out of data or reach the end of the current
        // frame's data
        const uint32_t remaining_frame_payload =
            session_data->remaining_frame_octets[source_id] -
            session_data->padding_octets_in_frame[source_id];
        octets_to_copy = remaining_frame_payload > len - data_offset ? len - data_offset :
            remaining_frame_payload;
        if (octets_to_copy > 0)
        {
            memcpy(session_data->frame_data[source_id] + session_data->frame_data_offset[source_id],
                data + data_offset, octets_to_copy);
        }
        session_data->frame_data_offset[source_id] += octets_to_copy;
        session_data->remaining_frame_octets[source_id] -= octets_to_copy;
        data_offset += octets_to_copy;

        if (data_offset == len)
            break;

        // Skip over any padding
        uint32_t padding_bytes_to_skip = session_data->padding_octets_in_frame[source_id] >
            len - data_offset ? len - data_offset :
            session_data->padding_octets_in_frame[source_id];
        session_data->remaining_frame_octets[source_id] -= padding_bytes_to_skip;
        data_offset += padding_bytes_to_skip;

        if (data_offset == len)
            break;

        // Copy headers
        const uint32_t remaining_frame_header =  FRAME_HEADER_LENGTH -
            (session_data->frame_header_offset[source_id] % FRAME_HEADER_LENGTH);
        octets_to_copy = remaining_frame_header > len - data_offset ? len - data_offset :
            remaining_frame_header;
        memcpy(session_data->frame_header[source_id] + session_data->frame_header_offset[source_id],
            data + data_offset, octets_to_copy);
        session_data->frame_header_offset[source_id] += octets_to_copy;
        data_offset += octets_to_copy;

        if (session_data->frame_header_offset[source_id] % FRAME_HEADER_LENGTH != 0)
            break;

        // If we just finished copying a header, parse and update frame variables
        session_data->remaining_frame_octets[source_id] =
            get_frame_length(session_data->frame_header[source_id] +
            session_data->frame_header_offset[source_id] - FRAME_HEADER_LENGTH);

        uint8_t frame_flags = get_frame_flags(session_data->frame_header[source_id] +
            session_data->frame_header_offset[source_id] - FRAME_HEADER_LENGTH);
        if (frame_flags & PADDED)
            session_data->get_padding_len[source_id] = true;
    } while (data_offset < len);

    if (flags & PKT_PDU_TAIL)
    {
        session_data->total_bytes_in_split[source_id] = 0;
        session_data->num_frame_headers[source_id] = 0;
        session_data->scan_octets_seen[source_id] = 0;

        // Return 0-length non-null buffer to stream which signals detection required, but don't 
        // create pkt_data buffer
        frame_buf.data = (const uint8_t*)"";
    }
    session_data->frame_type[source_id] = get_frame_type(session_data->frame_header[source_id]);

    return frame_buf;
}

ValidationResult validate_preface(const uint8_t* data, const uint32_t length, 
    const uint32_t octets_seen)
{
    const uint32_t preface_length = 24;

    static const uint8_t connection_prefix[] = {'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P',
        '/', '2', '.', '0', '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n'};

    assert(octets_seen < preface_length);

    const uint32_t count = (octets_seen + length) < preface_length ? length :
        (preface_length - octets_seen);

    if (memcmp(data, connection_prefix + octets_seen, count))
        return V_BAD;

    if ((octets_seen + length) < preface_length)
        return V_TBD;
    
    return V_GOOD;
}
