/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2003-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

//
//  @author     Tom Peters <thopeter@cisco.com>
//
//  @brief      HTTP Stream Splitter Class
//

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include "snort.h"
#include "protocols/packet.h"
#include "nhttp_enum.h"
#include "nhttp_test_manager.h"
#include "nhttp_test_input.h"
#include "nhttp_splitter.h"
#include "nhttp_stream_splitter.h"
#include "nhttp_inspect.h"

using namespace NHttpEnums;

// Convenience function. All the housekeeping that must be done before we can return FLUSH to stream.
void NHttpStreamSplitter::prepare_flush(NHttpFlowData* session_data, uint32_t* flush_offset, SourceId source_id,
      SectionType section_type, bool tcp_close, uint64_t infractions, uint32_t num_octets, uint32_t length) {
    assert(num_octets > 0);
    session_data->section_type[source_id] = section_type;
    session_data->tcp_close[source_id] = tcp_close;
    session_data->infractions[source_id] = infractions;
    if (tcp_close) {
        session_data->type_expected[source_id] = SEC_CLOSED;
    }
    if (!NHttpTestManager::use_test_input()) {
        *flush_offset = num_octets;
    }
    else {
        NHttpTestManager::get_test_input_source()->flush(num_octets);
    }
    session_data->peek_ahead_octets[source_id] = 0;
    session_data->unused_octets_visible[source_id] = length - num_octets;
    session_data->header_octets_visible[source_id] = 0;
}

StreamSplitter::Status NHttpStreamSplitter::scan (Flow* flow, const uint8_t* data, uint32_t length, uint32_t, uint32_t* flush_offset) {
    assert(length <= 63780);

    // When the system begins providing TCP connection close information this won't always be false. FIXIT-H
    bool tcp_close = false;

    // This is the session state information we share with HTTP Inspect and store with stream. A session is defined
    // by a TCP connection. Since PAF is the first to see a new TCP connection the new flow data object is created here.
    NHttpFlowData* session_data = (NHttpFlowData*)flow->get_application_data(NHttpFlowData::nhttp_flow_id);
    if (session_data == nullptr) flow->set_application_data(session_data = new NHttpFlowData);
    assert(session_data != nullptr);

    SourceId source_id = to_server() ? SRC_CLIENT : SRC_SERVER;

    if (NHttpTestManager::use_test_input()) {
        // This block substitutes a completely new data buffer supplied by the test tool in place of the "real" data.
        // It also rewrites the buffer length, source ID, and TCP close indicator.
        *flush_offset = length;
        bool need_break;
        uint8_t* test_data = nullptr;
        NHttpTestManager::get_test_input_source()->scan(test_data, length, source_id, tcp_close, need_break);
        if (length == 0) {
            return StreamSplitter::FLUSH;
        }
        data = test_data;
        if (need_break) {
            session_data = new NHttpFlowData;
            flow->set_application_data(session_data);
        }
        assert(session_data->type_expected[source_id] != SEC_ABORT);
        assert(session_data->type_expected[source_id] != SEC_CLOSED);
    }

    SectionType type = session_data->type_expected[source_id];

    // Check for header section previously found during peek ahead
    if ((type == SEC_HEADER) && (session_data->header_octets_visible[source_id] > 0)) {
        prepare_flush(session_data, flush_offset, source_id, type,
           tcp_close && (session_data->header_octets_visible[source_id] == length),
           0, session_data->header_octets_visible[source_id], length);
        return StreamSplitter::FLUSH;
    }
    // Did we peek ahead and not find the complete headers?
    if (session_data->peek_ahead_octets[source_id] > 0) {
        assert(length == session_data->peek_ahead_octets[source_id]);
        session_data->peek_ahead_octets[source_id] = 0;
        return StreamSplitter::SEARCH;
    }

    switch (type) {
      case SEC_REQUEST:
      case SEC_STATUS:
      case SEC_CHUNKHEAD:
      case SEC_HEADER:
      case SEC_TRAILER: {
        paf_max = 63780;
        NHttpSplitter* splitter = ((type == SEC_HEADER) || (type == SEC_TRAILER)) ?
           (NHttpSplitter*)&session_data->header_splitter[source_id] :
           (NHttpSplitter*)&session_data->start_splitter[source_id];
        const uint32_t max_length = (length <= (63780 - splitter->get_octets_seen())) ? length :
           (63780 - splitter->get_octets_seen());
        const SectionType split_result = splitter->split(data, max_length);
        if (split_result == SEC__NOTPRESENT) {
            if (splitter->get_octets_seen() == 63780) {
                // FIXIT-M need to implement processing and detection instead of just discarding this data
                session_data->type_expected[source_id] = SEC_ABORT;
                return StreamSplitter::ABORT;
            }
            if (!tcp_close) {
                // Incomplete headers wait patiently for more data
                return StreamSplitter::SEARCH;
            }
            prepare_flush(session_data, flush_offset, source_id, type, true, INF_TRUNCATED, length, length);
            splitter->reset();
            return StreamSplitter::FLUSH;
        }
        const uint32_t flush_octets = session_data->peek_ahead_octets[source_id] + splitter->get_num_flush();
        if (split_result == SEC_DISCARD) {
            prepare_flush(session_data, flush_offset, source_id, SEC_DISCARD, tcp_close && (flush_octets == length), 0,
               flush_octets, length);
            splitter->reset();
            return StreamSplitter::FLUSH;
        }
        prepare_flush(session_data, flush_offset, source_id, type, tcp_close && (flush_octets == length), 0,
           flush_octets, length);
        splitter->reset();
        if ((type == SEC_REQUEST) || (type == SEC_STATUS)) {
            // Look ahead to see if entire header section is already here so we can aggregate it for detection.
            NHttpSplitter* peek_splitter = &session_data->header_splitter[source_id];
            const SectionType peek_result = peek_splitter->split(data + flush_octets, length - flush_octets);
            if (peek_result == SEC_HEADER) {
                session_data->header_octets_visible[source_id] = peek_splitter->get_num_flush();
                peek_splitter->reset();
            }
            else {
                session_data->peek_ahead_octets[source_id] = length - flush_octets;
            }
        }
        return StreamSplitter::FLUSH;
      }
      case SEC_BODY:
      case SEC_CHUNKBODY:
        paf_max = 16384 - session_data->chunk_buffer_length[source_id];
        if ((!tcp_close) || (length > session_data->data_length[source_id])) {
            prepare_flush(session_data, flush_offset, source_id, type, false, 0, session_data->data_length[source_id],
               length);
        }
        else {
            // The TCP connection has closed and this is the possibly incomplete final section
            prepare_flush(session_data, flush_offset, source_id, type, true, 0, length, length);
        }
        return StreamSplitter::FLUSH;
      case SEC_ABORT:
        return StreamSplitter::ABORT;
      default:
        assert(0);
        return StreamSplitter::ABORT;
    }
}

const StreamBuffer* NHttpStreamSplitter::reassemble(Flow* flow, unsigned /*total FIXIT-H */, unsigned offset, const uint8_t* data,
       unsigned len, uint32_t flags, unsigned& copied)
{
    static THREAD_LOCAL StreamBuffer nhttp_buf;

    NHttpFlowData* session_data = (NHttpFlowData*)flow->get_application_data(NHttpFlowData::nhttp_flow_id);
    SourceId source_id = to_server() ? SRC_CLIENT : SRC_SERVER;
    copied = len;

    if (NHttpTestManager::use_test_input()) {
        if (!(flags & PKT_PDU_TAIL))
        {
            return nullptr;
        }
        uint8_t* test_buffer;
        NHttpTestManager::get_test_input_source()->reassemble(&test_buffer, len, source_id, session_data);
        if (len == 0) {
            // There is no more test data
            return nullptr;
        }
        data = test_buffer;
        offset = 0;
    }

    bool is_chunk_body = session_data->section_type[source_id] == SEC_CHUNKBODY;

    uint8_t*& chunk_buffer = session_data->chunk_buffer[source_id];
    int32_t& chunk_buffer_length = session_data->chunk_buffer_length[source_id];
    uint8_t*& buffer = !is_chunk_body ? session_data->section_buffer[source_id] : chunk_buffer;
    int32_t& buffer_length = !is_chunk_body ? session_data->section_buffer_length[source_id] : chunk_buffer_length;

    if (buffer == nullptr) {
        buffer = new uint8_t[65536];
    }

    memcpy(buffer + buffer_length + offset, data, len);
    if (flags & PKT_PDU_TAIL) {
        ProcessResult send_to_detection;
        if (!is_chunk_body) {
            // start line/headers/body individual section processing with aggregation prior to being sent to detection
            // only the last section added to the buffer goes to the inspector
            send_to_detection = my_inspector->process(buffer + buffer_length, offset + len, flow, source_id,
               buffer_length == 0);
        }
        else {
            // Because of aggregation chunk body sections do not go to Inspector on schedule or in chronological order
            // with respect to otherchunks. That means NHttpMsgChunkBody::update_flow() cannot do it design-intended
            // job of updating type_expected in time for StreamSplitter to find the next chunk header. So we do it here.
            session_data->type_expected[source_id] = SEC_CHUNKHEAD;

            // small chunks are aggregated before processing and are kept here until the buffer is full (paf_max)
            // all the chunks in the buffer go to the inspector together
            int32_t total_chunk_len = chunk_buffer_length + offset + len;
            if (total_chunk_len < 16384) {
                paf_max = 16384 - total_chunk_len;
                chunk_buffer_length = total_chunk_len;
                return nullptr;
            }
            else {
                paf_max = 16384;
            }
            send_to_detection = my_inspector->process(chunk_buffer, total_chunk_len, flow, source_id, true);
        }

        // Buffers are reset to nullptr without delete[] because NHttpMsgSection holds the pointer and is responsible
        switch (send_to_detection) {
          case RES_INSPECT:
            nhttp_buf.data = buffer;
            nhttp_buf.length = buffer_length + offset + len;
            buffer = nullptr;
            buffer_length = 0;
            if (NHttpTestManager::use_test_output()) {
                fprintf(NHttpTestManager::get_output_file(), "Sent to detection %u octets\n\n", nhttp_buf.length);
            }
            return &nhttp_buf;
          case RES_IGNORE:
            buffer = nullptr;
            buffer_length = 0;
            return nullptr;
          case RES_AGGREGATE:
            buffer_length += offset + len;
            return nullptr;
          case RES_FLUSHCHUNKS:
            buffer = nullptr;
            buffer_length = 0;
            if (chunk_buffer != nullptr) {
                // FIXIT-M these three variables about the buffered chunks need to be managed properly
                session_data->section_type[source_id] = SEC_CHUNKBODY;
                session_data->tcp_close[source_id] = false;
                session_data->infractions[source_id] = 0;

                my_inspector->process(chunk_buffer, chunk_buffer_length, flow, source_id, true);
                nhttp_buf.data = chunk_buffer;
                nhttp_buf.length = chunk_buffer_length;
                chunk_buffer = nullptr;
                chunk_buffer_length = 0;
                if (NHttpTestManager::use_test_output()) {
                    fprintf(NHttpTestManager::get_output_file(), "Flushed chunks for detection %u octets\n\n", nhttp_buf.length);
                }
                return &nhttp_buf;
            }
            return nullptr;
        }
    }
    return nullptr;
}






























