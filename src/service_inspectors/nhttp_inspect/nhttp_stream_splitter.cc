//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// Convenience function. All housekeeping that must be done before we can return FLUSH to stream.
void NHttpStreamSplitter::prepare_flush(NHttpFlowData* session_data, uint32_t* flush_offset,
    SectionType section_type, uint32_t num_flushed, uint32_t octets_seen, uint32_t num_excess,
    int32_t num_head_lines) const
{
    session_data->section_type[source_id] = section_type;
    session_data->num_excess[source_id] = num_excess;
    session_data->num_head_lines[source_id] = num_head_lines;
    session_data->flush_size[source_id] = num_flushed + octets_seen;

    if (!NHttpTestManager::use_test_input())
    {
        *flush_offset = num_flushed;
    }
    else
    {
        NHttpTestManager::get_test_input_source()->flush(num_flushed);
    }
}

NHttpSplitter* NHttpStreamSplitter::get_splitter(SectionType type,
    const NHttpFlowData* session_data) const
{
    switch (type)
    {
    case SEC_REQUEST: return (NHttpSplitter*)new NHttpRequestSplitter;
    case SEC_STATUS: return (NHttpSplitter*)new NHttpStatusSplitter;
    case SEC_HEADER:
    case SEC_TRAILER: return (NHttpSplitter*)new NHttpHeaderSplitter;
    case SEC_BODY: return (NHttpSplitter*)new NHttpBodySplitter(
        session_data->data_length[source_id]);
    case SEC_CHUNK: return (NHttpSplitter*)new NHttpChunkSplitter;
    default: assert(0); return nullptr;
    }
}

void NHttpStreamSplitter::chunk_spray(NHttpFlowData* session_data, uint8_t* buffer,
    const uint8_t* data, unsigned length) const
{
    uint8_t* buf = buffer + session_data->chunk_offset[source_id];
    ChunkState& curr_state = session_data->chunk_state[source_id];
    uint32_t& expected = session_data->chunk_expected[source_id];
    for (uint32_t k=0; k < length; k++)
    {
        switch (curr_state)
        {
        case CHUNK_NUMBER:
            if (data[k] == '\r')
                curr_state = CHUNK_HCRLF;
            else if (data[k] == ';')
                curr_state = CHUNK_OPTIONS;
            else
                expected = expected * 16 + as_hex[data[k]];
            break;
        case CHUNK_OPTIONS:
            if (data[k] == '\r')
                curr_state = CHUNK_HCRLF;
            break;
        case CHUNK_HCRLF:
            if (expected > 0)
                curr_state = CHUNK_DATA;
            else
            {
                // Terminating zero-length chunk
                assert(k+1 == length);
                curr_state = CHUNK_NUMBER;
            }
            break;
        case CHUNK_DATA:
          {
            const uint32_t skip_amount = (length-k <= expected) ? length-k : expected;
            memcpy(buf, data+k, skip_amount);
            buf += skip_amount;
            if ((expected -= skip_amount) == 0)
                curr_state = CHUNK_DCRLF1;
            k += skip_amount-1;
            break;
          }
        case CHUNK_DCRLF1:
            curr_state = CHUNK_DCRLF2;
            break;
        case CHUNK_DCRLF2:
            curr_state = CHUNK_NUMBER;
            expected = 0;
            break;
        case CHUNK_ZEROS:
            // Not a possible state in reassemble(). Here to avoid compiler warning.
            assert(0);
            break;
        }
    }
    session_data->chunk_offset[source_id] = buf - buffer;
}

StreamSplitter::Status NHttpStreamSplitter::scan(Flow* flow, const uint8_t* data, uint32_t length,
    uint32_t, uint32_t* flush_offset)
{
    assert(length <= MAX_OCTETS);

    // This is the session state information we share with NHttpInspect and store with stream. A
    // session is defined by a TCP connection. Since scan() is the first to see a new TCP
    // connection the new flow data object is created here.
    NHttpFlowData* session_data = (NHttpFlowData*)flow->get_application_data(
        NHttpFlowData::nhttp_flow_id);
    if (session_data == nullptr)
    {
        flow->set_application_data(session_data = new NHttpFlowData);
    }
    assert(session_data != nullptr);

    if (NHttpTestManager::use_test_input())
    {
        // This block substitutes a completely new data buffer supplied by the test tool in place
        // of the "real" data. It also rewrites the buffer length and TCP close indicator.
        *flush_offset = length;
        bool need_break;
        uint8_t* test_data = nullptr;
        NHttpTestManager::get_test_input_source()->scan(test_data, length, source_id, need_break);
        if (need_break)
        {
            session_data = new NHttpFlowData;
            flow->set_application_data(session_data);
        }
        if (length == 0)
        {
            return StreamSplitter::FLUSH;
        }
        data = test_data;
        if (session_data->type_expected[source_id] == SEC_ABORT)
        {
            session_data = new NHttpFlowData;
            flow->set_application_data(session_data);
        }
    }
    else if (NHttpTestManager::use_test_output())
    {
        printf("Scan from flow data %" PRIu64 " direction %d length %u\n", session_data->seq_num,
            source_id, length);
        fflush(stdout);
    }

    const SectionType type = session_data->type_expected[source_id];

    if ((type == SEC_ABORT) || (session_data->tcp_close[source_id]))
        return StreamSplitter::ABORT;

    NHttpSplitter*& splitter = session_data->splitter[source_id];
    if (splitter == nullptr)
    {
        splitter = get_splitter(type, session_data);
        assert(splitter != nullptr);
    }
    const uint32_t max_length = MAX_OCTETS - splitter->get_octets_seen();
    const ScanResult split_result = splitter->split(data, (length <= max_length) ? length :
        max_length, session_data->infractions[source_id], session_data->events[source_id]);
    switch (split_result)
    {
    case SCAN_NOTFOUND:
        if (splitter->get_octets_seen() == MAX_OCTETS)
        {
            session_data->infractions[source_id] += INF_ENDLESS_HEADER;
            session_data->events[source_id].create_event(EVENT_LOSS_OF_SYNC);
            // FIXIT-H need to process this data not just discard it.
            session_data->type_expected[source_id] = SEC_ABORT;
            delete splitter;
            splitter = nullptr;
            if (!NHttpTestManager::use_test_input())
            {
                return StreamSplitter::ABORT;
            }
            else
            {
                NHttpTestManager::get_test_input_source()->discard(length);
                return StreamSplitter::FLUSH;
            }
        }
        // Incomplete headers wait patiently for more data
        return NHttpTestManager::use_test_input() ? StreamSplitter::FLUSH : StreamSplitter::SEARCH;
    case SCAN_ABORT:
    case SCAN_FLUSH_ABORT: // FIXIT-M add support for this
        session_data->type_expected[source_id] = SEC_ABORT;
        delete splitter;
        splitter = nullptr;
        if (!NHttpTestManager::use_test_input())
        {
            return StreamSplitter::ABORT;
        }
        else
        {
            NHttpTestManager::get_test_input_source()->discard(length);
            return StreamSplitter::FLUSH;
        }
    case SCAN_DISCARD:
        prepare_flush(session_data, flush_offset, SEC_DISCARD, splitter->get_num_flush(),
            splitter->get_octets_seen(), 0, 0);
        delete splitter;
        splitter = nullptr;
        return StreamSplitter::FLUSH;
    case SCAN_FOUND:
    case SCAN_FOUND_PIECE:
      {
        const uint32_t flush_octets = splitter->get_num_flush();
        prepare_flush(session_data, flush_offset, type, flush_octets, splitter->get_octets_seen(),
            splitter->get_num_excess(), splitter->get_num_head_lines());
        if (split_result == SCAN_FOUND)
        {
            delete splitter;
            splitter = nullptr;
        }
        return StreamSplitter::FLUSH;
      }
    default:
        assert(0);
        return StreamSplitter::ABORT;
    }
}

const StreamBuffer* NHttpStreamSplitter::reassemble(Flow* flow, unsigned total, unsigned offset,
    const uint8_t* data, unsigned len, uint32_t flags, unsigned& copied)
{
    static THREAD_LOCAL StreamBuffer nhttp_buf;

    copied = len;

    assert(total >= offset + len);
    assert(total <= MAX_OCTETS);

    NHttpFlowData* session_data = (NHttpFlowData*)flow->get_application_data(
        NHttpFlowData::nhttp_flow_id);
    assert(session_data != nullptr);

    if (NHttpTestManager::use_test_output())
    {
        if (NHttpTestManager::use_test_input())
        {
            if (!(flags & PKT_PDU_TAIL))
            {
                return nullptr;
            }
            bool tcp_close;
            uint8_t* test_buffer;
            NHttpTestManager::get_test_input_source()->reassemble(&test_buffer, len, source_id,
                tcp_close);
            if (tcp_close)
            {
                finish(flow);
            }
            if (test_buffer == nullptr)
            {
                // Source ID does not match test data, no test data was flushed, or there is no
                // more test data
                return nullptr;
            }
            data = test_buffer;
            offset = 0;
            total = len;
        }
        else
        {
            printf("Reassemble from flow data %" PRIu64
                " direction %d total %u length %u offset %u\n",
                session_data->seq_num, source_id, total, len, offset);
            fflush(stdout);
        }
    }

    if (session_data->section_type[source_id] == SEC__NOTCOMPUTE)
    {   // FIXIT-M In theory this check should not be necessary
        return nullptr;
    }

    // FIXIT-P stream should be enhanced to do discarding for us. For now flush-then-discard here
    // is how scan() handles things we don't need to examine.
    if (session_data->section_type[source_id] == SEC_DISCARD)
    {
        if (NHttpTestManager::use_test_output())
        {
            fprintf(NHttpTestManager::get_output_file(), "Discarded %u octets\n\n", len);
            fflush(NHttpTestManager::get_output_file());
        }
        session_data->section_type[source_id] = SEC__NOTCOMPUTE;
        return nullptr;
    }

    uint8_t*& buffer = session_data->section_buffer[source_id];

    if (buffer == nullptr)
    {
        if ((session_data->section_type[source_id] == SEC_BODY) ||
            (session_data->section_type[source_id] == SEC_CHUNK))
        {
            buffer = NHttpInspect::body_buffer;
        }
        else
        {
            buffer = new uint8_t[total];
        }
    }

    if (session_data->section_type[source_id] != SEC_CHUNK)
    {
        memcpy(buffer + offset, data, len);
    }
    else
    {
        chunk_spray(session_data, buffer, data, len);
    }

    if (flags & PKT_PDU_TAIL)
    {
        const bool not_chunk = session_data->section_type[source_id] != SEC_CHUNK;

        if (session_data->flush_size[source_id] < offset + len)
        {   // FIXIT-M In theory this check should not be necessary
            if (not_chunk && (session_data->section_type[source_id] != SEC_BODY))
            {
                delete[] buffer;
            }
            buffer = nullptr;
            return nullptr;
        }

        const uint32_t section_length = not_chunk ? offset + len :
            session_data->chunk_offset[source_id];
        session_data->chunk_offset[source_id] = 0;

        const bool send_to_detection = my_inspector->process(buffer,
            section_length - session_data->num_excess[source_id], flow, source_id,
            not_chunk && (session_data->section_type[source_id] != SEC_BODY));

        // Buffers are reset to nullptr without delete[] because NHttpMsgSection holds the pointer
        // and is responsible
        if (send_to_detection)
        {
            nhttp_buf.data = buffer;
            nhttp_buf.length = section_length;
            assert((nhttp_buf.length <= MAX_OCTETS) && (nhttp_buf.length != 0));
            buffer = nullptr;
            if (NHttpTestManager::use_test_output())
            {
                fprintf(NHttpTestManager::get_output_file(), "Sent to detection %u octets\n\n",
                    nhttp_buf.length);
                fflush(NHttpTestManager::get_output_file());
            }
            return &nhttp_buf;
        }
        my_inspector->clear(session_data, source_id);
        buffer = nullptr;
    }
    return nullptr;
}

bool NHttpStreamSplitter::finish(Flow* flow)
{
    NHttpFlowData* session_data = (NHttpFlowData*)flow->get_application_data(
        NHttpFlowData::nhttp_flow_id);
    if (session_data == nullptr) // FIXIT-H this should not be necessary
    {
        return false;
    }
    assert(session_data != nullptr);
    session_data->tcp_close[source_id] = true;
    // If there is leftover data for which we returned PAF_SEARCH and never flushed, we need to set
    // up to process because it is about to go to reassemble(). But we don't support partial start
    // lines.
    // FIXIT-L Partial start line is likely misidentifed traffic and should be some sort of alert
    if ((session_data->section_type[source_id] == SEC__NOTCOMPUTE) &&
        (session_data->splitter[source_id] != nullptr) &&
        (session_data->splitter[source_id]->get_octets_seen() > 0) &&
        (session_data->type_expected[source_id] != SEC_ABORT))
    {
        if ((session_data->type_expected[source_id] == SEC_REQUEST) ||
            (session_data->type_expected[source_id] == SEC_STATUS))
        {
            return false;
        }
        session_data->section_type[source_id] = session_data->type_expected[source_id];
        session_data->num_excess[source_id] = 0;
        session_data->num_head_lines[source_id] =
            session_data->splitter[source_id]->get_num_head_lines() + 1;
        session_data->flush_size[source_id] = session_data->splitter[source_id]->get_octets_seen();
    }
    return true;
}

