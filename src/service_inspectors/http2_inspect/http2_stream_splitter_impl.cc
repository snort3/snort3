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
    else
       return FT__NONE;
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
        switch (validate_preface(data, length, session_data->octets_seen[source_id]))
        {
            case V_GOOD:
                break;
            case V_BAD:
                session_data->events[source_id]->create_event(EVENT_PREFACE_MATCH_FAILURE);
                return StreamSplitter::ABORT;
            case V_TBD:
                session_data->octets_seen[source_id] += length;
                return StreamSplitter::SEARCH;
        }

        *flush_offset = 24 - session_data->octets_seen[source_id];
        session_data->header_coming[source_id] = false;
        session_data->preface[source_id] = false;
        session_data->payload_discard[source_id] = true;
    }
    else if (session_data->leftover_data[source_id] > 0)
    {
        // Continuation of ongoing data frame
        session_data->header_coming[source_id] = false;
 
        // If this is a new section, update next inspection_section_length
        if (session_data->octets_seen[source_id] == 0)
        {
            if (session_data->leftover_data[source_id] > DATA_SECTION_SIZE)
                session_data->inspection_section_length[source_id] = DATA_SECTION_SIZE;
            else
                 session_data->inspection_section_length[source_id] = 
                     session_data->leftover_data[source_id];
        }

        // Don't have full inspection section, keep scanning
        if (session_data->octets_seen[source_id] + length < 
            session_data->inspection_section_length[source_id])
        {
            session_data->octets_seen[source_id] += length;
            return status = StreamSplitter::SEARCH;
        } 

        // Have full inspection section, flush and update leftover
        *flush_offset = session_data->inspection_section_length[source_id];
        session_data->leftover_data[source_id] -=
            session_data->inspection_section_length[source_id];
        session_data->octets_seen[source_id] = 0;
    }
    else
    {
        // frame with header
        // If there is a header frame followed by a continuation frame in the same tcp segment,
        // need to process multiple frames in a single scan
        *flush_offset = 0;
        uint32_t remaining_length = length;    
        const uint8_t *data_pos = data;
        do
        {
            if (session_data->scan_header_octets_seen[source_id] == 0)
            {
                session_data->header_coming[source_id] = true;
                session_data->octets_seen[source_id] = 0;
            }

            // The first nine bytes are the frame header. But all nine might not all be present in
            // the first TCP segment we receive.
            if (session_data->scan_header_octets_seen[source_id] < FRAME_HEADER_LENGTH)
            {
                uint32_t remaining_header = FRAME_HEADER_LENGTH -
                    session_data->scan_header_octets_seen[source_id];
                uint32_t remaining_header_in_data = remaining_header > remaining_length ?
                    remaining_length : remaining_header;
                memcpy(session_data->currently_processing_frame_header[source_id] +
                    session_data->scan_header_octets_seen[source_id],
                    data_pos, remaining_header_in_data);
                session_data->scan_header_octets_seen[source_id] += remaining_header_in_data;
                if (session_data->scan_header_octets_seen[source_id] < FRAME_HEADER_LENGTH)
                {
                    session_data->octets_seen[source_id] += remaining_header_in_data;
                    status = StreamSplitter::SEARCH;
                    break;
                }
                session_data->frames_aggregated[source_id] += 1;
            }
            
            uint8_t type = get_frame_type(session_data->currently_processing_frame_header[source_id]);

            if (session_data->continuation_expected[source_id] && type != FT_CONTINUATION)
            {
                *session_data->infractions[source_id] += INF_MISSING_CONTINUATION;
                session_data->events[source_id]->create_event(EVENT_MISSING_CONTINUATION);
                status = StreamSplitter::ABORT;
                break;
            }

            // Frame length does not include the frame header
            uint32_t const frame_length = get_frame_length(session_data->
                currently_processing_frame_header[source_id]);

            // For non-data frames, send a full frame to detection
            session_data->inspection_section_length[source_id] = frame_length + FRAME_HEADER_LENGTH;

            if ((type == FT_DATA) && (frame_length > DATA_SECTION_SIZE))
            {
                // Break up long data frames into pieces for detection
                session_data->inspection_section_length[source_id] = DATA_SECTION_SIZE +
                    FRAME_HEADER_LENGTH;
            }
            else if (frame_length + FRAME_HEADER_LENGTH > MAX_OCTETS)
            {
                // FIXIT-M long non-data frame needs to be supported
                status = StreamSplitter::ABORT;
                break;
            }

            if (length + session_data->octets_seen[source_id] < 
                session_data->inspection_section_length[source_id])
            {
                // If we don't have the full inspection length, keep scanning
                session_data->octets_seen[source_id] += length;
                status = StreamSplitter::SEARCH;
                break;
            }
            else
            {
                // we have the full frame section to flush to detection
                *flush_offset += session_data->inspection_section_length[source_id] -
                    session_data->octets_seen[source_id];
                session_data->leftover_data[source_id] = frame_length + FRAME_HEADER_LENGTH 
                    - session_data->inspection_section_length[source_id];
                session_data->octets_seen[source_id] = 0;
            }

            // Process all header frames as one unit - if the END_HEADERS flag is not set and scan 
            // is out of data, tell stream to keep searching 
            uint8_t frame_flags = get_frame_flags(session_data->
                    currently_processing_frame_header[source_id]);
            if (type == FT_HEADERS && !(frame_flags & END_HEADERS))
            {
                session_data->continuation_expected[source_id] = true;
                
                session_data->scan_header_octets_seen[source_id] = 0;
                status = StreamSplitter::SEARCH;
                data_pos = data + *flush_offset;
                remaining_length = length - *flush_offset;
            }
            else if ( type == FT_CONTINUATION && session_data->continuation_expected[source_id])
            {
                if (!(frame_flags & END_HEADERS))
                {
                    session_data->scan_header_octets_seen[source_id] = 0;
                    status = StreamSplitter::SEARCH;
                    data_pos = data + *flush_offset;
                    remaining_length = length - *flush_offset;
                }
                else
                {
                    // continuation frame ending headers
                    status = StreamSplitter::FLUSH;
                    session_data->continuation_expected[source_id] = false;
                }
            }
            //FIXIT-M CONTINUATION frames can also follow PUSH_PROMISE frames, which is not
            //currently supported
            else if (type == FT_CONTINUATION)
            {
                *session_data->infractions[source_id] += INF_UNEXPECTED_CONTINUATION;
                session_data->events[source_id]->create_event(EVENT_UNEXPECTED_CONTINUATION);
                status = StreamSplitter::ABORT;
            }
        } while (status == StreamSplitter::SEARCH && remaining_length > 0);
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

    StreamBuffer frame_buf { nullptr, 0 };

    if (offset == 0)
    {
        // This is the first reassemble() for this frame and we need to allocate some buffers
        if (!session_data->header_coming[source_id])
            session_data->frame_data[source_id] = new uint8_t[total];
        else
        {
            const uint32_t header_length = FRAME_HEADER_LENGTH * 
                session_data->frames_aggregated[source_id];
            session_data->frame_header[source_id] = new uint8_t[header_length];
            session_data->frame_header_size[source_id] = header_length;
            if (total > FRAME_HEADER_LENGTH)
                session_data->frame_data[source_id] = new uint8_t[total - header_length];
        }
        session_data->reassemble_header_octets_seen[source_id] = 0;
        session_data->frame_data_size[source_id] = 0;
        session_data->frame_header_offset[source_id] = 0;
    }

    if (!session_data->header_coming[source_id])
    {
        memcpy(session_data->frame_data[source_id] + offset, data, len);
        session_data->frame_data_size[source_id] += len;
    }
    else
    {
        uint32_t data_pos = 0;
        do
        {
            // Each pass through the loop handles one frame
            // Multiple frames occur when a Headers frame and Continuation frame(s) are flushed
            // together
            uint32_t remaining_len = len - data_pos;

            // Process the frame header
            if (session_data->reassemble_header_octets_seen[source_id] < FRAME_HEADER_LENGTH)
            {
                uint8_t remaining_header = FRAME_HEADER_LENGTH -
                    session_data->reassemble_header_octets_seen[source_id];
                if (remaining_header > remaining_len)
                {
                    memcpy(session_data->frame_header[source_id] +
                        session_data->frame_header_offset[source_id] +
                        session_data->reassemble_header_octets_seen[source_id], data + data_pos,
                        remaining_len);
                    session_data->reassemble_header_octets_seen[source_id] += remaining_len;
                    break;
                }
                memcpy(session_data->frame_header[source_id] +
                    session_data->frame_header_offset[source_id] +
                    session_data->reassemble_header_octets_seen[source_id], data + data_pos,
                    remaining_header);
                session_data->reassemble_header_octets_seen[source_id] += remaining_header;
                data_pos += remaining_header;
                remaining_len -= remaining_header;
            }

            // done once per frame after we have the entire header
            if (session_data->remaining_frame_data_octets[source_id] == 0)
            {
                uint32_t frame_length = 0;
                uint32_t frame_data_offset = 0;
                uint8_t pad_len = 0;
                uint8_t frame_flags = 0;

                frame_length = get_frame_length(session_data->frame_header[source_id] +
                    session_data->frame_header_offset[source_id]);
                frame_flags = get_frame_flags(session_data->frame_header[source_id] +
                    session_data->frame_header_offset[source_id]);

                if (frame_flags & PADDED)
                {
                    frame_data_offset += 1;
                    pad_len = session_data->frame_data[source_id][0];
                }
                //FIXIT-M handle stream dependency and weight. For now just skip over
                if (frame_flags & PRIORITY)
                {
                    frame_data_offset += 5;
                }
                session_data->remaining_octets_to_next_header[source_id] = frame_length;
                session_data->remaining_frame_data_octets[source_id] =
                    frame_length - pad_len - frame_data_offset;
                session_data->remaining_frame_data_offset[source_id] = frame_data_offset;
            }

            if (remaining_len >= session_data->remaining_octets_to_next_header[source_id])
            {
                // have the remainder of the full frame
                memcpy(session_data->frame_data[source_id] + session_data->frame_data_size[source_id],
                    data + data_pos + session_data->remaining_frame_data_offset[source_id],
                    session_data->remaining_frame_data_octets[source_id]);
                session_data->frame_data_size[source_id] +=
                    session_data->remaining_frame_data_octets[source_id];
                data_pos += session_data->remaining_octets_to_next_header[source_id];
                session_data->remaining_octets_to_next_header[source_id] = 0;
                session_data->remaining_frame_data_octets[source_id] = 0;
                session_data->remaining_frame_data_offset[source_id] = 0;
                session_data->reassemble_header_octets_seen[source_id] = 0;
                session_data->frame_header_offset[source_id] += FRAME_HEADER_LENGTH;
            }
            else if (remaining_len < session_data->remaining_frame_data_offset[source_id])
            {
                // don't have the full stream dependency/weight, which precedes frame data
                session_data->remaining_frame_data_offset[source_id] -= remaining_len;
                session_data->remaining_octets_to_next_header[source_id] -= remaining_len;
                return frame_buf;
            }
            else if (remaining_len < session_data->remaining_frame_data_octets[source_id])
            {
                // don't have the full frame data
                uint32_t data_len = remaining_len - session_data->remaining_frame_data_offset[source_id];
                memcpy(session_data->frame_data[source_id] + session_data->frame_data_size[source_id],
                    data + data_pos + session_data->remaining_frame_data_offset[source_id],
                    data_len);
                session_data->frame_data_size[source_id] += data_len;
                session_data->remaining_octets_to_next_header[source_id] -= remaining_len;
                session_data->remaining_frame_data_octets[source_id] -= data_len;
                session_data->remaining_frame_data_offset[source_id] = 0;
                return frame_buf;
            }
            else
            {
                // have all the data but not all the padding following the data
                memcpy(session_data->frame_data[source_id] + session_data->frame_data_size[source_id],
                    data + data_pos + session_data->remaining_frame_data_offset[source_id],
                    session_data->remaining_frame_data_octets[source_id]);
                session_data->frame_data_size[source_id] +=
                    session_data->remaining_frame_data_octets[source_id];
                session_data->remaining_octets_to_next_header[source_id] -= remaining_len;
                session_data->remaining_frame_data_octets[source_id] = 0;
                session_data->remaining_frame_data_offset[source_id] = 0;
            }
        } while (data_pos < len);
    }

    if (flags & PKT_PDU_TAIL)
    {
        if (session_data->header_coming[source_id])
        {
            if (get_frame_type(session_data->frame_header[source_id]) == FT_HEADERS)
            {
                assert(session_data->raw_decoded_header[source_id] == nullptr);

                // FIXIT-H This will eventually be the decoded header buffer. Under development.
                if (!Http2Hpack::decode_headers(session_data, source_id,
                    session_data->frame_data[source_id], session_data->frame_data_size[source_id]))
                {
                    // Since this doesn't go to detection, clear() doesn't get called, so need to
                    // clear frame data from flow data directly
                    session_data->clear_frame_data(source_id);

                    session_data->frame_type[source_id] = FT__ABORT;
                    return frame_buf;
                }
            }
        }
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
