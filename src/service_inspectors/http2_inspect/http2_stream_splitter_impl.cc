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

#include "protocols/packet.h"
#include "service_inspectors/http_inspect/http_common.h"
#include "service_inspectors/http_inspect/http_field.h"
#include "service_inspectors/http_inspect/http_test_input.h"
#include "service_inspectors/http_inspect/http_test_manager.h"

#include "http2_flow_data.h"
#include "http2_hpack_int_decode.h"
#include "http2_hpack_string_decode.h"
#include "http2_stream_splitter.h"

using namespace snort;
using namespace HttpCommon;
using namespace Http2Enums;

#define STATIC_TABLE_MAX_INDEX 61

// FIXIT-H remove these declarations once implemented, for some reason this makes the compiler
// happy for build alt
bool decode_static_table_index(void);
bool decode_dynamic_table_index(void);

Http2HpackIntDecode Http2StreamSplitter::decode_int7(7);
Http2HpackIntDecode Http2StreamSplitter::decode_int6(6);
Http2HpackIntDecode Http2StreamSplitter::decode_int5(5);
Http2HpackIntDecode Http2StreamSplitter::decode_int4(4);
Http2HpackStringDecode Http2StreamSplitter::decode_string;

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
        session_data->leftover_data[source_id] -=
            session_data->inspection_section_length[source_id];
        session_data->octets_seen[source_id] = 0;
    }
    else
    {
        // frame with header
        // If there is a header frame followed by a continuation frame in the same tcp segment, need
        // to process multiple frames in a single scan
        *flush_offset = 0;
        uint32_t remaining_length = length;    
        const uint8_t *data_pos = data;
        do
        {
            if (session_data->header_octets_seen[source_id] == 0)
            {
                session_data->header_coming[source_id] = true;
                session_data->octets_seen[source_id] = 0;
                session_data->header_octets_seen[source_id] = 0;
            }

            // The first nine bytes are the frame header. But all nine might not all be present in
            // the first TCP segment we receive.
            if (session_data->header_octets_seen[source_id] < FRAME_HEADER_LENGTH)
            {
                uint32_t remaining_header = FRAME_HEADER_LENGTH -
                    session_data->header_octets_seen[source_id];
                uint32_t remaining_header_in_data = remaining_header > remaining_length ?
                    remaining_length : remaining_header;
                memcpy(session_data->currently_processing_frame_header[source_id] +
                    session_data->header_octets_seen[source_id],
                    data_pos, remaining_header_in_data);
                session_data->header_octets_seen[source_id] += remaining_header_in_data;
                if (session_data->header_octets_seen[source_id] < FRAME_HEADER_LENGTH)
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
                
                session_data->header_octets_seen[source_id] = 0;
                status = StreamSplitter::SEARCH;
                data_pos = data + *flush_offset;
                remaining_length = length - *flush_offset;
            }
            else if ( type == FT_CONTINUATION && session_data->continuation_expected[source_id])
            {
                if (!(frame_flags & END_HEADERS))
                {
                    session_data->header_octets_seen[source_id] = 0;
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
        session_data->header_octets_seen[source_id] = 0;
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
            uint32_t remaining_len = len - data_pos;

            if (session_data->header_octets_seen[source_id] < FRAME_HEADER_LENGTH)
            {
                uint8_t remaining_header = FRAME_HEADER_LENGTH -
                    session_data->header_octets_seen[source_id];
                if (remaining_header > remaining_len)
                {
                    memcpy(session_data->frame_header[source_id] +
                        session_data->frame_header_offset[source_id] +
                        session_data->header_octets_seen[source_id], data + data_pos,
                        remaining_len);
                    session_data->header_octets_seen[source_id] += remaining_len;
                    break;
                }
                memcpy(session_data->frame_header[source_id] +
                    session_data->frame_header_offset[source_id] +
                    session_data->header_octets_seen[source_id], data + data_pos,
                    remaining_header);
                session_data->header_octets_seen[source_id] += remaining_header;
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
                session_data->remaining_frame_data_octets[source_id] = frame_length - pad_len - frame_data_offset;
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
                session_data->header_octets_seen[source_id] = 0;
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
            const uint8_t type = get_frame_type(session_data->frame_header[source_id]);

            if (type == FT_HEADERS || type == FT_CONTINUATION)
            {
                assert(session_data->http2_decoded_header[source_id] == nullptr);

                //FIXIT-H This will eventually be the decoded header buffer. For now just copy
                //directly
				if (!decode_headers(session_data, source_id, session_data->frame_data[source_id],
                        session_data->frame_data_size[source_id]))
                    return frame_buf;
            }
        }
        // Return 0-length non-null buffer to stream which signals detection required, but don't 
        // create pkt_data buffer
        frame_buf.length = 0;
        if (session_data->frame_data[source_id])
            frame_buf.data = session_data->frame_data[source_id];
        else
            frame_buf.data = session_data->frame_header[source_id];
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

bool write_decoded_headers(Http2FlowData* session_data, HttpCommon::SourceId source_id,
    const uint8_t* in_buffer, const uint32_t in_length,
    uint8_t* decoded_header_buffer, uint32_t decoded_header_length,
    uint32_t &bytes_written)
{
    bool ret = true;
    uint32_t length = in_length;
    bytes_written = 0;

    if (in_length > decoded_header_length)
    {
        length = MAX_OCTETS - session_data->http2_decoded_header_size[source_id];
        *session_data->infractions[source_id] += INF_DECODED_HEADER_BUFF_OUT_OF_SPACE;
        session_data->events[source_id]->create_event(EVENT_MISFORMATTED_HTTP2);
        ret = false;
    }

    memcpy((void*)decoded_header_buffer, (void*) in_buffer, length);
    bytes_written = length;
    return ret;
}

bool decode_string_literal(Http2FlowData* session_data, HttpCommon::SourceId source_id,
    const uint8_t* encoded_header_buffer, const uint32_t encoded_header_length,
    const Http2HpackStringDecode &decode_string, bool is_field_name, uint32_t &bytes_consumed,
    uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
    uint32_t &bytes_written)
{
    uint32_t decoded_bytes_written;
    uint32_t encoded_bytes_consumed;
    uint32_t encoded_header_offset = 0;
    bytes_written = 0;
    bytes_consumed = 0;

    if (is_field_name)
    {
        // skip over parsed pattern and zeroed index
        encoded_header_offset++;
        bytes_consumed++;
    }

    if (!decode_string.translate(encoded_header_buffer + encoded_header_offset,
        encoded_header_length, encoded_bytes_consumed, decoded_header_buffer,
        decoded_header_length, decoded_bytes_written, session_data->events[source_id],
        session_data->infractions[source_id]))
    {
        return false;
    }

    bytes_consumed += encoded_bytes_consumed;
    bytes_written += decoded_bytes_written;

    if (is_field_name)
    {
        if (!write_decoded_headers(session_data, source_id, (const uint8_t*)": ", 2,
                decoded_header_buffer + bytes_written, decoded_header_length -
                bytes_written, decoded_bytes_written))
            return false;
    }
    else
    {
        if (!write_decoded_headers(session_data, source_id, (const uint8_t*)"\r\n", 2,
                decoded_header_buffer + bytes_written, decoded_header_length -
                bytes_written, decoded_bytes_written))
            return false;
    }

    bytes_written += decoded_bytes_written;

    return true;
}

// FIXIT-H implement
bool decode_static_table_index(void)
{
    return false;
}

// FIXIT-H implement
bool decode_dynamic_table_index(void)
{
    return false;
}

// FIXIT-H Will be incrementally updated to actually decode indexes. For now just copies encoded
// index directly to decoded_header_buffer
bool decode_index(Http2FlowData* session_data, HttpCommon::SourceId source_id,
    const uint8_t* encoded_header_buffer, const uint32_t encoded_header_length,
    const Http2HpackIntDecode &decode_int, uint32_t &bytes_consumed,
    uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
    uint32_t &bytes_written)
{
    uint64_t index;
    bytes_written = 0;
    bytes_consumed = 0;

    if (!decode_int.translate(encoded_header_buffer, encoded_header_length,
        bytes_consumed, index, session_data->events[source_id],
        session_data->infractions[source_id]))
    {
        return false;
    }

    if (index <= STATIC_TABLE_MAX_INDEX)
        decode_static_table_index();
    else
        decode_dynamic_table_index();

    if (!write_decoded_headers(session_data, source_id, encoded_header_buffer, bytes_consumed,
            decoded_header_buffer, decoded_header_length, bytes_written))
        return false;

    return true;
}

bool decode_literal_header_line(Http2FlowData* session_data, HttpCommon::SourceId source_id,
    const uint8_t* encoded_header_buffer, const uint32_t encoded_header_length,
    const uint8_t name_index_mask, const Http2HpackIntDecode &decode_int, uint32_t &bytes_consumed,
    uint8_t* decoded_header_buffer, const uint32_t decoded_header_length,
    uint32_t &bytes_written)
{
    bytes_written = 0;
    bytes_consumed = 0;
    uint32_t partial_bytes_consumed;
    uint32_t partial_bytes_written;
 
    // indexed field name
    if (encoded_header_buffer[0] & name_index_mask)
    {
        if (!decode_index(session_data, source_id, encoded_header_buffer,
                encoded_header_length, decode_int, partial_bytes_consumed,
                decoded_header_buffer, decoded_header_length, partial_bytes_written))
            return false;
    }
    // literal field name
    else
    {
        if (!decode_string_literal(session_data, source_id, encoded_header_buffer,
                encoded_header_length, Http2StreamSplitter::decode_string, true,
                partial_bytes_consumed, decoded_header_buffer, decoded_header_length,
                partial_bytes_written))
            return false;
    }

    bytes_consumed += partial_bytes_consumed;
    bytes_written += partial_bytes_written;

    // value is always literal
    if (!decode_string_literal(session_data, source_id, encoded_header_buffer +
            partial_bytes_consumed, encoded_header_length - partial_bytes_consumed,
            Http2StreamSplitter::decode_string, false, partial_bytes_consumed,
            decoded_header_buffer + partial_bytes_written, decoded_header_length -
            partial_bytes_written, partial_bytes_written))
        return false;

    bytes_consumed += partial_bytes_consumed;
    bytes_written += partial_bytes_written;

    return true;
}

// FIXIT-M Will be updated to actually update dynamic table size. For now just skips over
bool handle_dynamic_size_update(Http2FlowData* session_data, HttpCommon::SourceId source_id,
    const uint8_t* encoded_header_buffer, const uint32_t encoded_header_length,
    const Http2HpackIntDecode &decode_int, uint32_t &bytes_consumed, uint32_t &bytes_written)
{
    uint64_t decoded_int;
    uint32_t encoded_bytes_consumed;
    bytes_consumed = 0;
    bytes_written = 0;

    if (!decode_int.translate(encoded_header_buffer, encoded_header_length,
        encoded_bytes_consumed, decoded_int, session_data->events[source_id],
        session_data->infractions[source_id]))
    {
        return false;
    }
#ifdef REG_TEST
    //FIXIT-M remove when dynamic size updates are handled
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2))
    {
            fprintf(HttpTestManager::get_output_file(),
                "Skipping HPACK dynamic size update: %lu\n", decoded_int);
    }
#endif
    bytes_consumed += encoded_bytes_consumed;

    return true;
}

bool decode_header_line(Http2FlowData* session_data, HttpCommon::SourceId source_id,
    const uint8_t* encoded_header_buffer, const uint32_t encoded_header_length,
    uint32_t& bytes_consumed, uint8_t* decoded_header_buffer,
    const uint32_t decoded_header_length, uint32_t& bytes_written)
{
    const uint8_t index_mask = 0x80;
    const uint8_t literal_index_mask = 0x40;
    const uint8_t literal_index_name_index_mask = 0x3f;
    const uint8_t literal_no_index_mask = 0xf0;
    const uint8_t literal_never_index_pattern = 0x10;
    const uint8_t literal_no_index_name_index_mask = 0x0f;

    // indexed header representation
    if (encoded_header_buffer[0] & index_mask)
        return decode_index(session_data, source_id, encoded_header_buffer, encoded_header_length,
            Http2StreamSplitter::decode_int7, bytes_consumed, decoded_header_buffer,
            decoded_header_length, bytes_written);

    // literal header representation to be added to dynamic table
    else if (encoded_header_buffer[0] & literal_index_mask)
        return decode_literal_header_line(session_data, source_id, encoded_header_buffer,
             encoded_header_length, literal_index_name_index_mask,
             Http2StreamSplitter::decode_int6, bytes_consumed, decoded_header_buffer,
             decoded_header_length, bytes_written);

    // literal header field representation not to be added to dynamic table
    // Note that this includes two representation types from the RFC - literal without index and
    // literal never index. From a decoding standpoint these are identical.
    else if ((encoded_header_buffer[0] & literal_no_index_mask) == 0 or
            (encoded_header_buffer[0] & literal_no_index_mask) == literal_never_index_pattern)
        return decode_literal_header_line(session_data, source_id, encoded_header_buffer,
             encoded_header_length, literal_no_index_name_index_mask,
             Http2StreamSplitter::decode_int4, bytes_consumed, decoded_header_buffer,
             decoded_header_length, bytes_written);
    else
        // FIXIT-M dynamic table size update not yet supported, just skip
        return handle_dynamic_size_update(session_data, source_id, encoded_header_buffer,
            encoded_header_length, Http2StreamSplitter::decode_int5, bytes_consumed, bytes_written);
}

//FIXIT-H This will eventually be the decoded header buffer. For now only string literals are
//decoded
bool decode_headers(Http2FlowData* session_data, HttpCommon::SourceId source_id,
    const uint8_t* encoded_header_buffer, const uint32_t header_length)
{

    uint32_t total_bytes_consumed = 0;
    uint32_t line_bytes_consumed = 0;
    uint32_t line_bytes_written = 0;
    bool success = true;
    session_data->http2_decoded_header[source_id] = new uint8_t[MAX_OCTETS];
    session_data->http2_decoded_header_size[source_id] = 0;

    while (total_bytes_consumed < header_length)
    {
        if (!decode_header_line(session_data, source_id,
            encoded_header_buffer + total_bytes_consumed, header_length - total_bytes_consumed,
            line_bytes_consumed, session_data->http2_decoded_header[source_id] +
            session_data->http2_decoded_header_size[source_id], MAX_OCTETS -
            session_data->http2_decoded_header_size[source_id], line_bytes_written))
        {
            success = false;
            break;
        }
        total_bytes_consumed  += line_bytes_consumed;
        session_data->http2_decoded_header_size[source_id] += line_bytes_written;
    }

    if (!success)
    {
#ifdef REG_TEST
        if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2))
        {
            fprintf(HttpTestManager::get_output_file(),
                    "Error decoding headers. ");
            if(session_data->http2_decoded_header_size[source_id] > 0)
                Field(session_data->http2_decoded_header_size[source_id],
                    session_data->http2_decoded_header[source_id]).print(
                    HttpTestManager::get_output_file(), "Partially Decoded Header");
        }
#endif
    return false;
    }

    // write the last crlf to end the header
    if (!write_decoded_headers(session_data, source_id, (const uint8_t*)"\r\n", 2,
            session_data->http2_decoded_header[source_id] +
            session_data->http2_decoded_header_size[source_id], MAX_OCTETS -
            session_data->http2_decoded_header_size[source_id], line_bytes_written))
        return false;
    session_data->http2_decoded_header_size[source_id] += line_bytes_written;

#ifdef REG_TEST
	if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP2))
	{
		Field(session_data->http2_decoded_header_size[source_id],
			session_data->http2_decoded_header[source_id]).print(HttpTestManager::get_output_file(),
            "Decoded Header");
	}
#endif

    return success;
}
