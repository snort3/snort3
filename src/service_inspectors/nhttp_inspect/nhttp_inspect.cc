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
// nhttp_inspect.cc author Tom Peters <thopeter@cisco.com>

#include <assert.h>
#include <stdio.h>

#include "stream/stream_api.h"
#include "nhttp_enum.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_status.h"
#include "nhttp_msg_header.h"
#include "nhttp_msg_body.h"
#include "nhttp_msg_chunk.h"
#include "nhttp_msg_trailer.h"
#include "nhttp_test_manager.h"
#include "nhttp_inspect.h"

using namespace NHttpEnums;

NHttpInspect::NHttpInspect(bool test_input, bool test_output)
{
    if (test_input) {
        NHttpTestManager::activate_test_input();
    }
    if (test_output) {
        NHttpTestManager::activate_test_output();
    }
}

bool NHttpInspect::get_buf(InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    switch ( ibt )
    {
    case InspectionBuffer::IBT_KEY:
        return get_buf(HTTP_BUFFER_URI, p, b);

    case InspectionBuffer::IBT_HEADER:
        return get_buf(HTTP_BUFFER_HEADER, p, b);

    case InspectionBuffer::IBT_BODY:
        return get_buf(HTTP_BUFFER_CLIENT_BODY, p, b);

    default:
        return false;
    }   
}

bool NHttpInspect::get_buf(unsigned id, Packet*, InspectionBuffer& b)
{
    const HttpBuffer* h = GetHttpBuffer((HTTP_BUFFER)id);

    if (!h) {
        return false;
    }

    b.data = h->buf;
    b.len = h->length;
    return true;
}

ProcessResult NHttpInspect::process(const uint8_t* data, const uint16_t dsize, Flow* const flow, SourceId source_id,
   bool buf_owner)
{
    NHttpFlowData* session_data = (NHttpFlowData*)flow->get_application_data(NHttpFlowData::nhttp_flow_id);
    assert(session_data != nullptr);

    NHttpMsgSection *msg_section = nullptr;

    switch (session_data->section_type[source_id]) {
      case SEC_REQUEST: msg_section = new NHttpMsgRequest(data, dsize, session_data, source_id, buf_owner); break;
      case SEC_STATUS: msg_section = new NHttpMsgStatus(data, dsize, session_data, source_id, buf_owner); break;
      case SEC_HEADER: msg_section = new NHttpMsgHeader(data, dsize, session_data, source_id, buf_owner); break;
      case SEC_BODY: msg_section = new NHttpMsgBody(data, dsize, session_data, source_id, buf_owner); break;
      case SEC_CHUNK: msg_section = new NHttpMsgChunk(data, dsize, session_data, source_id, buf_owner); break;
      case SEC_TRAILER: msg_section = new NHttpMsgTrailer(data, dsize, session_data, source_id, buf_owner); break;
      default: assert(0); if (buf_owner) delete[] data; return RES_IGNORE;
    }

    msg_section->analyze();
    msg_section->update_flow();
    msg_section->gen_events();

    ProcessResult return_value = msg_section->worth_detection();
    if (return_value == RES_INSPECT) {
        msg_section->legacy_clients();
    }

    if (NHttpTestManager::use_test_output()) {
        msg_section->print_section(NHttpTestManager::get_output_file());
        fflush(NHttpTestManager::get_output_file());
        if (NHttpTestManager::use_test_input()) {
            printf("Finished processing section from test %" PRIi64 "\n", NHttpTestManager::get_test_number());
        }
        else {
            printf("Finished processing section from flow %p\n", (void*)session_data);
        }
        fflush(stdout);
    }

    return return_value;
}

