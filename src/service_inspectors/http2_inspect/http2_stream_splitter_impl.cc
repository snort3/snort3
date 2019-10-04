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

#include <cassert>

#include "http2_stream_splitter.h"
#include "protocols/packet.h"
#include "service_inspectors/http_inspect/http_common.h"

#include "http2_flow_data.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

static uint32_t get_frame_length(const uint8_t *frame_buffer)
{
    return (frame_buffer[0] << 16) + (frame_buffer[1] << 8) + frame_buffer[2];
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
                // FIXIT-H: Workaround till abort is implemented
                if((session_data->octets_seen[source_id] + length) >= 24)
                    break;
                // Falls through
            case V_TBD:
                session_data->octets_seen[source_id] += length;
                return StreamSplitter::SEARCH;
        }

        *flush_offset = 24 - session_data->octets_seen[source_id];
        session_data->header_coming[source_id] = false;
        session_data->preface[source_id] = false;
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
        session_data->leftover_data[source_id] -= session_data->inspection_section_length[source_id];
        session_data->octets_seen[source_id] = 0;
    }
    else
    {
        // frame with header
        // If there is a header frame followed by a continuation frame in the same tcp segment, 
        // need to process multiple frames in a single scan
        *flush_offset = 0;
        do
        {
            if (session_data->frame_header[source_id] == nullptr)
            {
                session_data->header_coming[source_id] = true;
                session_data->frame_header[source_id] = new uint8_t[FRAME_HEADER_LENGTH];
                session_data->octets_seen[source_id] = 0;
                session_data->header_octets_seen[source_id] = 0;
            }

            // The first nine bytes are the frame header. But all nine might not all be present in the
            // first TCP segment we receive. 
            for (uint32_t k = 0; (k < length) && (session_data->header_octets_seen[source_id] <
                        FRAME_HEADER_LENGTH); k++, session_data->header_octets_seen[source_id]++)
            {
                session_data->frame_header[source_id][session_data->header_octets_seen[source_id]] = data[k];
            }
            if (session_data->header_octets_seen[source_id] < FRAME_HEADER_LENGTH)
            {
                session_data->octets_seen[source_id] += length;
                status = StreamSplitter::SEARCH;
                break;
            }
            int type = session_data->get_frame_type(source_id);

            // Frame length does not include the frame header
            uint32_t const frame_length = get_frame_length(session_data->frame_header[source_id]);

            // For non-data frames, send a full frame to detection
            session_data->inspection_section_length[source_id] = frame_length + FRAME_HEADER_LENGTH;

            if ((type == FT_DATA) && (frame_length > DATA_SECTION_SIZE))
            {
                // Break up long data frames into pieces for detection
                session_data->inspection_section_length[source_id] = DATA_SECTION_SIZE + FRAME_HEADER_LENGTH;
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
                *flush_offset += session_data->inspection_section_length[source_id] - session_data->octets_seen[source_id];
                session_data->leftover_data[source_id] = frame_length + FRAME_HEADER_LENGTH 
                    - session_data->inspection_section_length[source_id];
                session_data->octets_seen[source_id] = 0;
            }

            // Process all header frames as one unit - if the END_HEADERS flag is not set and scan 
            // is out of data, tell stream to keep searching 
            if (type == FT_HEADERS && !(session_data->get_frame_flags(source_id) & END_HEADERS))
            {
                session_data->continuation_expected = true;
                // We need to save the header frame header for reassembly
                session_data->header_frame_header[source_id] = new uint8_t[FRAME_HEADER_LENGTH];
                memcpy(session_data->header_frame_header[source_id], 
                    session_data->frame_header[source_id], FRAME_HEADER_LENGTH);
                
                delete[] session_data->frame_header[source_id];
                session_data->frame_header[source_id] = nullptr;
                status = StreamSplitter::SEARCH;
                data += frame_length + FRAME_HEADER_LENGTH;
            }
            else if ( type == FT_CONTINUATION && session_data->continuation_expected)
            {
                if (!(session_data->get_frame_flags(source_id) & END_HEADERS))
                {
                    // For continuation frames we only need the frame length
                    // FIXIT-M Need to verify that continuation frame has correct stream id
                    session_data->continuation_frame_lengths.push_back(frame_length);
                
                    delete[] session_data->frame_header[source_id];
                    session_data->frame_header[source_id] = nullptr;
                    status = StreamSplitter::SEARCH;
                    data += frame_length + FRAME_HEADER_LENGTH;
                }
                else
                {
                    // continuation frame ending headers
                    status = StreamSplitter::FLUSH;
                    session_data->continuation_expected = false;
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
            else if (session_data->continuation_expected)
            {
                *session_data->infractions[source_id] += INF_MISSING_CONTINUATION;
                session_data->events[source_id]->create_event(EVENT_MISSING_CONTINUATION);
                status = StreamSplitter::ABORT;
            }
        } while (status != StreamSplitter::FLUSH && *flush_offset < length);
    }
    return status;
}

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
        session_data->frame[source_id] = new uint8_t[total];
        session_data->frame_size[source_id] = total;
    }
    assert(session_data->frame_size[source_id] == total);
    
    memcpy(session_data->frame[source_id]+offset, data, len);

    if (flags & PKT_PDU_TAIL)
    {
        assert(offset+len == total);
        if (!session_data->header_coming[source_id])
        {
            session_data->frame_data[source_id] = session_data->frame[source_id];
            session_data->frame_data_size[source_id] = session_data->frame_size[source_id];
        }
        else if (session_data->frame_size[source_id] == FRAME_HEADER_LENGTH)
        {
            session_data->frame_data[source_id] = nullptr;
            session_data->frame_data_size[source_id] = 0;
        }
        else
        {
            // Adjust for frame header
            session_data->frame_data[source_id] =
                session_data->frame[source_id] + FRAME_HEADER_LENGTH;
            session_data->frame_data_size[source_id] =
                session_data->frame_size[source_id] - FRAME_HEADER_LENGTH;

            const int type = session_data->get_frame_type(source_id);
        
            if (type == FT_HEADERS || type == FT_CONTINUATION)
            {
                assert(session_data->http2_decoded_header[source_id] == nullptr);
                session_data->http2_decoded_header[source_id] = new uint8_t[MAX_OCTETS];
                uint8_t header_payload_offset = 0;
                uint8_t pad_len = 0;

                uint8_t frame_flags;
                uint32_t header_frame_length;
                if (type == FT_HEADERS)
                {
                    frame_flags = session_data->get_frame_flags(source_id); 
                    header_frame_length = get_frame_length(session_data->frame_header[source_id]);
                }
                else
                {
                    assert(session_data->header_frame_header[source_id] != nullptr);
                    frame_flags = session_data->header_frame_header[source_id][4];
                    header_frame_length = get_frame_length(session_data->header_frame_header[source_id]);
                }

                if (frame_flags & PADDED)
                {
                    header_payload_offset += 1;
                    pad_len = session_data->frame_data[source_id][0];
                }
                //FIXIT-M handle stream dependency and weight. For now just skip over
                if (frame_flags & PRIORITY)
                {
                    header_payload_offset += 5;
                }

                //FIXIT-H This will eventually be the decoded header buffer. For now just copy directly
                uint32_t header_payload_len = header_frame_length - header_payload_offset - pad_len;
                memcpy(session_data->http2_decoded_header[source_id], session_data->frame_data[source_id] + 
                        header_payload_offset, header_payload_len);
                session_data->http2_decoded_header_size[source_id] = header_payload_len;

                // check for continuation frames, skipping over frame headers
                if (type == FT_CONTINUATION)
                {
                    header_payload_offset += header_payload_len + pad_len + FRAME_HEADER_LENGTH;
                    for (uint32_t continuation_length : session_data->continuation_frame_lengths)
                    {
                        assert(header_payload_offset + continuation_length < total);
                        assert(session_data->http2_decoded_header_size[source_id] + continuation_length < 
                                MAX_OCTETS);
                        memcpy(session_data->http2_decoded_header[source_id] + 
                                session_data->http2_decoded_header_size[source_id],
                                session_data->frame_data[source_id] + header_payload_offset, 
                                continuation_length);
                        session_data->http2_decoded_header_size[source_id] += continuation_length;
                        header_payload_offset += continuation_length + FRAME_HEADER_LENGTH;
                    }

                    // The last continuation frame header is stored in the frame_header buffer
                    uint32_t final_continuation_length = 
                        get_frame_length(session_data->frame_header[source_id]);
                    assert(header_payload_offset + final_continuation_length < total);
                    assert(session_data->http2_decoded_header_size[source_id] + 
                            final_continuation_length < MAX_OCTETS);
                    memcpy(session_data->http2_decoded_header[source_id] + 
                            session_data->http2_decoded_header_size[source_id],
                            session_data->frame_data[source_id] + header_payload_offset, 
                            final_continuation_length);
                    session_data->http2_decoded_header_size[source_id] += final_continuation_length;
                }
            }
        }
        // Return 0-length non-null buffer to stream which signals detection required, but don't 
        // create pkt_data buffer
        frame_buf.length = 0;
        frame_buf.data = session_data->frame[source_id];
    }
    return frame_buf;
}

ValidationResult validate_preface(const uint8_t* data, const uint32_t length, 
    const uint32_t octets_seen)
{
    const uint32_t preface_length = 24;

    static const uint8_t connection_prefix[] = {'P', 'R', 'I', ' ', '*', ' ',
      'H', 'T', 'T', 'P', '/', '2', '.', '0', '\r', '\n', '\r', '\n', 'S', 'M', 
      '\r', '\n', '\r', '\n'};

    assert(octets_seen < preface_length);

    const uint32_t count = (octets_seen + length) < preface_length ? length : (preface_length - octets_seen); 

    if (memcmp(data, connection_prefix + octets_seen, count))
        return V_BAD;

    if ((octets_seen + length) < preface_length)
        return V_TBD;
    
    return V_GOOD;
}
