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
#include "nhttp_test_input.h"
#include "nhttp_stream_splitter.h"
#include "nhttp_inspect.h"

using namespace NHttpEnums;

// Convenience function. All the housekeeping that must be done before we can return FLUSH to stream.
void NHttpStreamSplitter::prepare_flush(NHttpFlowData* session_data, uint32_t* flush_offset, SourceId source_id,
      SectionType section_type, bool tcp_close, uint64_t infractions, uint32_t num_octets) {
    session_data->section_type[source_id] = section_type;
    session_data->tcp_close[source_id] = tcp_close;
    session_data->infractions[source_id] = infractions;
    if (tcp_close) {
        session_data->type_expected[source_id] = SEC_CLOSED;
    }
    if (!NHttpTestInput::test_input) {
        *flush_offset = num_octets;
    }
    else {
        NHttpTestInput::test_input_source->flush(num_octets);
    }
    session_data->octets_seen[source_id] = 0;
    session_data->num_crlf[source_id] = 0;
}

const StreamBuffer* NHttpStreamSplitter::reassemble(Flow* flow, unsigned /*total*/, unsigned offset, const uint8_t* data,
       unsigned len, uint32_t flags, unsigned& copied)
{
    static THREAD_LOCAL StreamBuffer nhttp_buf;
    if (flags & PKT_PDU_HEAD) {
        section_buffer = new uint8_t[65536];
    }

    SourceId source_id = to_server() ? SRC_CLIENT : SRC_SERVER;

    copied = len;

    if (NHttpTestInput::test_input) {
        if (!(flags & PKT_PDU_TAIL))
        {
            return nullptr;
        }
        uint8_t* buffer;
        NHttpTestInput::test_input_source->reassemble(&buffer, len, source_id);
        if (len == 0) {
            // There is no more test data
            delete[] section_buffer;
            section_buffer = nullptr;
            return nullptr;
        }
        data = buffer;
        offset = 0;
    }

    memcpy(section_buffer+offset, data, len);
    if (flags & PKT_PDU_TAIL) {
        my_inspector->process(section_buffer, offset + len, flow, source_id);
        nhttp_buf.data = section_buffer;
        nhttp_buf.length = offset + len;
        section_buffer = nullptr;   // the buffer is the responsibility of the inspector now
        return &nhttp_buf;
    }
    return nullptr;
}

StreamSplitter::Status NHttpStreamSplitter::scan (Flow* flow, const uint8_t* data, uint32_t length, uint32_t, uint32_t* flush_offset) {
    // When the system begins providing TCP connection close information this won't always be false. &&&
    bool tcp_close = false;

    // This is the session state information we share with HTTP Inspect and store with stream. A session is defined
    // by a TCP connection. Since PAF is the first to see a new TCP connection the new flow data object is created here.
    NHttpFlowData* session_data = (NHttpFlowData*)flow->get_application_data(NHttpFlowData::nhttp_flow_id);
    if (session_data == nullptr) flow->set_application_data(session_data = new NHttpFlowData);
    assert(session_data != nullptr);

    SourceId source_id = to_server() ? SRC_CLIENT : SRC_SERVER;

    if (NHttpTestInput::test_input) {
        // This block substitutes a completely new data buffer supplied by the test tool in place of the "real" data.
        // It also rewrites the buffer length, source ID, and TCP close indicator.
        *flush_offset = length;
        bool need_break;
        uint8_t* test_data = nullptr;
        NHttpTestInput::test_input_source->scan(test_data, length, source_id, tcp_close, need_break);
        if (length == 0) return StreamSplitter::FLUSH;
        data = test_data;
        if (need_break) flow->set_application_data(session_data = new NHttpFlowData);
    }

    switch (SectionType type = session_data->type_expected[source_id]) {
      case SEC_REQUEST:
      case SEC_STATUS:
      case SEC_HEADER:
      case SEC_CHUNKHEAD:
      case SEC_TRAILER:
        paf_max = 63780;
        for (uint32_t k = 0; k < length; k++) {
            session_data->octets_seen[source_id]++;
            // Count the alternating <CR> and <LF> characters we have seen in a row
            if (((data[k] == '\r') && (session_data->num_crlf[source_id]%2 == 0)) ||
                ((data[k] == '\n') && (session_data->num_crlf[source_id]%2 == 1))) {
                session_data->num_crlf[source_id]++;
            }
            else {
                session_data->num_crlf[source_id] = 0;
            }

            // Check start line for leading CRLF because some 1.0 implementations put extra blank lines between messages.
            // We tolerate this by quietly ignoring them. Header/trailer may also have leading CRLF. That is completely
            // normal and means there are no header/trailer lines.
            if ((session_data->num_crlf[source_id] == 2) && (session_data->octets_seen[source_id] == 2) && (type != SEC_CHUNKHEAD)) {
                prepare_flush(session_data, flush_offset, source_id,
                   ((type == SEC_REQUEST) || (type == SEC_STATUS)) ? SEC_DISCARD : type,
                   tcp_close && (k == length-1), 0, k+1);
                return StreamSplitter::FLUSH;
            }
            // The start line and chunk header section always end with the first <CRLF>
            else if ((session_data->num_crlf[source_id] == 2) &&
                     ((type == SEC_REQUEST) || (type == SEC_STATUS) || (type == SEC_CHUNKHEAD))) {
                prepare_flush(session_data, flush_offset, source_id, type, tcp_close && (k == length-1), 0, k+1);
                return StreamSplitter::FLUSH;
            }
            // The header and trailer sections always end with the first double <CRLF>
            else if (session_data->num_crlf[source_id] == 4) {
                prepare_flush(session_data, flush_offset, source_id, type, tcp_close && (k == length-1), 0, k+1);
                return StreamSplitter::FLUSH;
            }
            // We must do this to protect ourself from buffer overrun.
            else if (session_data->octets_seen[source_id] >= 63780) {
                prepare_flush(session_data, flush_offset, source_id, type, tcp_close && (k == length-1), INF_HEADTOOLONG, k+1);
                return StreamSplitter::FLUSH;
            }
        }
        // Incomplete headers wait patiently for more data
        if (!tcp_close) {
            return StreamSplitter::SEARCH;
        }
        // Discard the oddball case where the new "message" starts with <CR><close>
        else if ((session_data->octets_seen[source_id] == 1) && (session_data->num_crlf[source_id] == 1)) {
            prepare_flush(session_data, flush_offset, source_id, SEC_DISCARD, true, 0, length);
        }
        // TCP connection close, flush the partial header
        else {
            prepare_flush(session_data, flush_offset, source_id, type, true, INF_TRUNCATED, length);
        }
        return StreamSplitter::FLUSH;
      case SEC_BODY:
      case SEC_CHUNKBODY:
        paf_max = 16384;
        if ((!tcp_close) || (length > session_data->octets_expected[source_id])) {
            prepare_flush(session_data, flush_offset, source_id, type, false, 0, session_data->octets_expected[source_id]);
        }
        else {
            // The TCP connection has closed and this is the possibly incomplete final section
            prepare_flush(session_data, flush_offset, source_id, type, true,  0, length);
        }
        return StreamSplitter::FLUSH;
      case SEC_ABORT:
        return StreamSplitter::ABORT;
      default:
        assert(0);
        return StreamSplitter::ABORT;
    }
}


































