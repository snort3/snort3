/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// nhttp_stream_splitter.cc author Tom Peters <thopeter@cisco.com>

#include <assert.h>
#include <sys/types.h>

#include "nhttp_enum.h"
#include "nhttp_test_manager.h"
#include "nhttp_test_input.h"
#include "nhttp_splitter.h"
#include "nhttp_inspect.h"
#include "nhttp_stream_splitter.h"

using namespace NHttpEnums;

// Convenience function. All the housekeeping that must be done before we can return FLUSH to stream.
void NHttpStreamSplitter::prepare_flush(NHttpFlowData* session_data, uint32_t* flush_offset, SourceId source_id,
      SectionType section_type, bool tcp_close, uint64_t infractions, uint32_t num_octets, uint32_t length,
      uint32_t num_excess) {
    session_data->section_type[source_id] = section_type;
    session_data->num_excess[source_id] = num_excess;
    session_data->tcp_close[source_id] = tcp_close;
    session_data->infractions[source_id] = infractions;
    switch (section_type) {
      case SEC_BODY:
        paf_max = DATABLOCKSIZE;
        break;
      case SEC_CHUNK:
        paf_max = DATABLOCKSIZE - session_data->chunk_buffer_length[source_id];
        break;
      default:
        paf_max = MAXOCTETS;
        break;
    }
    if (tcp_close) {
        session_data->type_expected[source_id] = SEC_CLOSED;
    }

    // when TCP connection closes do not flush octets that have not arrived yet
    uint32_t flush_amount = (!tcp_close || (num_octets <= length)) ? num_octets : length;
    if (!NHttpTestManager::use_test_input()) {
        *flush_offset = flush_amount;
    }
    else {
        NHttpTestManager::get_test_input_source()->flush(flush_amount);
    }
    session_data->unused_octets_visible[source_id] = (length >= num_octets) ? length - num_octets : 0;
    session_data->header_octets_visible[source_id] = 0;
}

NHttpSplitter* NHttpStreamSplitter::choose_splitter(SectionType type, SourceId source_id,
   const NHttpFlowData* session_data) const {
    switch (type) {
      case SEC_REQUEST:
      case SEC_STATUS: return (NHttpSplitter*)&session_data->start_splitter[source_id];
      case SEC_CHUNK: return (NHttpSplitter*)&session_data->chunk_splitter[source_id];
      case SEC_HEADER:
      case SEC_TRAILER: return (NHttpSplitter*)&session_data->header_splitter[source_id];
      default: assert(0); return nullptr;
    }
}

StreamSplitter::Status NHttpStreamSplitter::scan (Flow* flow, const uint8_t* data, uint32_t length, uint32_t,
   uint32_t* flush_offset) {

    assert(length <= MAXOCTETS);

    /* FIXIT-L Temporary printf while we shake out stream interface */
    if (!NHttpTestManager::use_test_input() && NHttpTestManager::use_test_output()) {
        printf("scan() from flow %p direction %d\n", (void*)flow, 1 - (int)to_server());
        fflush(nullptr);
    }

    // When the system begins providing TCP connection close information this won't always be false. FIXIT-H
    bool tcp_close = false;

    // This is the session state information we share with NHttpInspect and store with stream. A session is defined
    // by a TCP connection. Since scan() is the first to see a new TCP connection the new flow data object is created
    // here.
    NHttpFlowData* session_data = (NHttpFlowData*)flow->get_application_data(NHttpFlowData::nhttp_flow_id);
    if (session_data == nullptr) {
        flow->set_application_data(session_data = new NHttpFlowData);
    }
    assert(session_data != nullptr);
    const SourceId source_id = to_server() ? SRC_CLIENT : SRC_SERVER;

    if (NHttpTestManager::use_test_input()) {
        // This block substitutes a completely new data buffer supplied by the test tool in place of the "real" data.
        // It also rewrites the buffer length and TCP close indicator.
        *flush_offset = length;
        bool need_break;
        uint8_t* test_data = nullptr;
        NHttpTestManager::get_test_input_source()->scan(test_data, length, source_id, tcp_close, need_break);
        if (need_break) {
            session_data = new NHttpFlowData;
            flow->set_application_data(session_data);
        }
        if (length == 0) {
            return StreamSplitter::FLUSH;
        }
        data = test_data;
        assert(session_data->type_expected[source_id] != SEC_ABORT);
        assert(session_data->type_expected[source_id] != SEC_CLOSED);
    }
    else if (NHttpTestManager::use_test_output()) {
        printf("Scan from flow data %p direction %d\n", (void*)session_data, source_id);
        fflush(stdout);
    }

    SectionType type = session_data->type_expected[source_id];

    switch (type) {
      case SEC_REQUEST:
      case SEC_STATUS:
      case SEC_CHUNK:
      case SEC_HEADER:
      case SEC_TRAILER:
      {
        NHttpSplitter* const splitter = choose_splitter(type, source_id, session_data);
        const uint32_t max_length = MAXOCTETS - splitter->get_octets_seen();
        const ScanResult split_result = splitter->split(data, (length <= max_length) ? length : max_length);
        switch (split_result) {
          case SCAN_NOTFOUND:
            if (splitter->get_octets_seen() == MAXOCTETS) {
                // FIXIT-H need to process this data (except chunk header) not just discard it.
                prepare_flush(session_data, flush_offset, source_id, SEC_DISCARD, tcp_close, 0, length, length, 0);
                session_data->type_expected[source_id] = SEC_ABORT;
                return StreamSplitter::FLUSH;
            }
            if (tcp_close) {
                if (splitter->partial_ok()) {
                    prepare_flush(session_data, flush_offset, source_id, type, true, INF_TRUNCATED, length, length,
                       splitter->get_num_excess());
                    return StreamSplitter::FLUSH;
                }
                else {
                    prepare_flush(session_data, flush_offset, source_id, SEC_DISCARD, true, 0, length, length, 0);
                    return StreamSplitter::FLUSH;
                }
            }
            // Incomplete headers wait patiently for more data
            return NHttpTestManager::use_test_input() ? StreamSplitter::FLUSH : StreamSplitter::SEARCH;
          case SCAN_ABORT:
            prepare_flush(session_data, flush_offset, source_id, SEC_DISCARD, tcp_close, 0, length, length, 0);
            session_data->type_expected[source_id] = SEC_ABORT;
            return StreamSplitter::FLUSH;
          case SCAN_DISCARD: {
            const uint32_t flush_octets = splitter->get_num_flush();
            prepare_flush(session_data, flush_offset, source_id, SEC_DISCARD, tcp_close && (flush_octets >= length), 0,
               flush_octets, length, 0);
            return StreamSplitter::FLUSH;
          }
          case SCAN_FOUND: {
            const uint32_t flush_octets = splitter->get_num_flush();
            prepare_flush(session_data, flush_offset, source_id, type, tcp_close && (flush_octets == length), 0,
               flush_octets, length, splitter->get_num_excess());
            if ((type == SEC_REQUEST) || (type == SEC_STATUS)) {
                // Look ahead to see if entire header section is already here so we can aggregate it for detection.
                 if (session_data->header_splitter[source_id].peek(data + flush_octets, length - flush_octets) == SCAN_FOUND) {
                    session_data->header_octets_visible[source_id] = session_data->header_splitter[source_id].get_num_flush();
                }
            }
            return StreamSplitter::FLUSH;
          }
        }
      }
      case SEC_BODY: {
        prepare_flush(session_data, flush_offset, source_id, SEC_BODY,
           tcp_close && (length <= session_data->data_length[source_id]),
           0, session_data->data_length[source_id], length, 0);
        return StreamSplitter::FLUSH;
      }
      case SEC_ABORT:
        return StreamSplitter::ABORT;
      default:
        assert(0);
        return StreamSplitter::ABORT;
    }
}

// FIXIT-P total is not used because it is not reliably correct. Could be used to compute required buffer size
// instead of always allocating the maximum
const StreamBuffer* NHttpStreamSplitter::reassemble(Flow* flow, unsigned total, unsigned offset,
       const uint8_t* data, unsigned len, uint32_t flags, unsigned& copied)
{
    static THREAD_LOCAL StreamBuffer nhttp_buf;

    // When the system begins providing TCP connection close information this won't always be false. FIXIT-H
    bool tcp_close = false;

    /* FIXIT-L Temporary printf while we shake out stream interface */
    if (!NHttpTestManager::use_test_input() && NHttpTestManager::use_test_output()) {
        printf("reassemble() from flow %p direction %d total %u length %u offset %u\n", (void*)flow, 1 - (int)to_server(), total, len, offset); fflush(nullptr);
    }

    NHttpFlowData* session_data = (NHttpFlowData*)flow->get_application_data(NHttpFlowData::nhttp_flow_id);
    assert(session_data != nullptr);
    SourceId source_id = to_server() ? SRC_CLIENT : SRC_SERVER;
    copied = len;

    if (NHttpTestManager::use_test_input()) {
        if (!(flags & PKT_PDU_TAIL))
        {
            return nullptr;
        }
        uint8_t* test_buffer;
        NHttpTestManager::get_test_input_source()->reassemble(&test_buffer, len, source_id, session_data, tcp_close);
        if (test_buffer == nullptr) {
            // Source ID does not match test data or there is no more test data
            return nullptr;
        }
        data = test_buffer;
        offset = 0;
    }
    else if (NHttpTestManager::use_test_output()) {
        printf("Reassemble from flow data %p direction %d\n", (void*)session_data, source_id);
        fflush(stdout);
    }

    if (session_data->section_type[source_id] == SEC__NOTCOMPUTE) {
        // FIXIT-M Apparently scan() did not flush this data. Probably Stream is flushing excess data while it prunes
        // a session. In any event it doesn't belong here because we cannot process it. Forward it to our parent class
        // for processing. There should be no more calls to scan() for this session but tell it to abort just in case.

        // session_data->type_expected[source_id] = SEC_ABORT; /* FIXIT-M this statement breaks the test tool */
        return StreamSplitter::reassemble(flow, total, offset, data, len, flags, copied);
    }

    session_data->tcp_close[source_id] = tcp_close || session_data->tcp_close[source_id];

    // FIXIT-P stream should be enhanced to do discarding for us. For now flush-then-discard here is how scan() handles
    // things we don't need to examine.
    if (session_data->section_type[source_id] == SEC_DISCARD) {
        if (NHttpTestManager::use_test_output()) {
            fprintf(NHttpTestManager::get_output_file(), "Discarded %u octets\n\n", len);
            fflush(NHttpTestManager::get_output_file());
        }
        session_data->section_type[source_id] = SEC__NOTCOMPUTE;
        return nullptr;
    }

    bool is_chunk = (session_data->section_type[source_id] == SEC_CHUNK);

    uint8_t*& chunk_buffer = session_data->chunk_buffer[source_id];
    int32_t& chunk_buffer_length = session_data->chunk_buffer_length[source_id];
    uint8_t*& buffer = !is_chunk ? session_data->section_buffer[source_id] : chunk_buffer;
    int32_t& buffer_length = !is_chunk ? session_data->section_buffer_length[source_id] : chunk_buffer_length;
    bool& buffer_owned = !is_chunk ? session_data->section_buffer_owned[source_id] :
       session_data->chunk_buffer_owned[source_id];

    if (buffer == nullptr) {
        buffer = new uint8_t[MAXOCTETS];
        assert(buffer != nullptr);
        buffer_owned = true;
    }

    uint32_t num_excess = session_data->num_excess[source_id];
    memcpy(buffer + buffer_length + offset, data, len);
    if (flags & PKT_PDU_TAIL) {
        ProcessResult send_to_detection;
        if (!is_chunk) {
            // start line/headers/body individual section processing with aggregation prior to being sent to detection
            // only the last section added to the buffer goes to the inspector
            send_to_detection = my_inspector->process(buffer + buffer_length, offset + len - num_excess, flow,
               source_id, buffer_length == 0);
        }
        else {
            // small chunks are aggregated before processing and are kept here until the buffer is full (paf_max)
            // all the chunks in the buffer go to the inspector together. Zero-length chunk (len == 1, num_excess == 1)
            // flushes accumulated chunks.
            int32_t total_chunk_len = chunk_buffer_length + offset + len - num_excess;
            if ((total_chunk_len < DATABLOCKSIZE) && (num_excess == 0) && !tcp_close) {
                chunk_buffer_length = total_chunk_len;
                return nullptr;
            }
            if (total_chunk_len == 0) {
                // Zero-length chunk cannot be processed by itself.
                delete[] chunk_buffer;
                chunk_buffer = nullptr;
                chunk_buffer_length = 0;
                // zero-length chunk is not visible to inspector. Transition to trailer must be handled here.
                session_data->section_type[source_id] = SEC__NOTCOMPUTE;
                session_data->type_expected[source_id] = SEC_TRAILER;
                return nullptr;
            }
            paf_max = DATABLOCKSIZE;
            send_to_detection = my_inspector->process(chunk_buffer, total_chunk_len, flow, source_id, true);
            if (num_excess > 0) {
                // zero-length chunk is not visible to inspector. Transition to trailer must be handled here.
                session_data->section_type[source_id] = SEC__NOTCOMPUTE;
                session_data->type_expected[source_id] = SEC_TRAILER;
            }
        }

        // Buffers are reset to nullptr without delete[] because NHttpMsgSection holds the pointer and is responsible
        switch (send_to_detection) {
          case RES_INSPECT:
            nhttp_buf.data = buffer;
            nhttp_buf.length = buffer_length + offset + len - num_excess;
            assert((nhttp_buf.length <= MAXOCTETS) && (nhttp_buf.length != 0));
            buffer = nullptr;
            buffer_length = 0;
            if (NHttpTestManager::use_test_output()) {
                fprintf(NHttpTestManager::get_output_file(), "Sent to detection %u octets\n\n", nhttp_buf.length);
                fflush(NHttpTestManager::get_output_file());
            }
            return &nhttp_buf;
          case RES_IGNORE:
            buffer = nullptr;
            buffer_length = 0;
            return nullptr;
          case RES_AGGREGATE:
            buffer_length += offset + len - num_excess;
            buffer_owned = false;
            return nullptr;
        }
    }
    return nullptr;
}






























