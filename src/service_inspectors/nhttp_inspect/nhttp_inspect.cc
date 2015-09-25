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
// nhttp_inspect.cc author Tom Peters <thopeter@cisco.com>

#include "nhttp_inspect.h"

#include <assert.h>
#include <stdio.h>

#include "stream/stream_api.h"
#include "detection/detection_util.h"

#include "nhttp_enum.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_status.h"
#include "nhttp_msg_header.h"
#include "nhttp_msg_body.h"
#include "nhttp_msg_chunk.h"
#include "nhttp_msg_trailer.h"
#include "nhttp_test_manager.h"
#include "nhttp_field.h"

using namespace NHttpEnums;

NHttpInspect::NHttpInspect(NHttpParaList params_) : params(params_)
{
#ifdef REG_TEST
    if (params.test_input)
    {
        NHttpTestManager::activate_test_input();
    }
    if (params.test_output)
    {
        NHttpTestManager::activate_test_output();
    }
#endif
}

THREAD_LOCAL uint8_t NHttpInspect::body_buffer[MAX_OCTETS];

THREAD_LOCAL NHttpMsgSection* NHttpInspect::latest_section = nullptr;

bool NHttpInspect::get_buf(InspectionBuffer::Type ibt, Packet*, InspectionBuffer& b)
{
    switch ( ibt )
    {
    case InspectionBuffer::IBT_KEY:
        return get_buf(HTTP_BUFFER_URI, nullptr, b);

    case InspectionBuffer::IBT_HEADER:
        return get_buf(HTTP_BUFFER_HEADER, nullptr, b);

    case InspectionBuffer::IBT_BODY:
        return get_buf(HTTP_BUFFER_CLIENT_BODY, nullptr, b);

    default:
        return false;
    }
}

bool NHttpInspect::get_buf(unsigned id, Packet*, InspectionBuffer& b)
{
    if (latest_section == nullptr)
        return false;

    const Field& legacy = latest_section->get_legacy(id);

    if (legacy.length <= 0)
        return false;

    b.data = legacy.start;
    b.len = legacy.length;
    return true;
}

bool NHttpInspect::process(const uint8_t* data, const uint16_t dsize, Flow* const flow,
    SourceId source_id, bool buf_owner) const
{
    NHttpFlowData* session_data = (NHttpFlowData*)flow->get_application_data(
        NHttpFlowData::nhttp_flow_id);
    assert(session_data != nullptr);

    switch (session_data->section_type[source_id])
    {
    case SEC_REQUEST:
        latest_section = new NHttpMsgRequest(data, dsize, session_data, source_id, buf_owner,
            flow, &params);
        break;
    case SEC_STATUS:
        latest_section = new NHttpMsgStatus(data, dsize, session_data, source_id, buf_owner, flow,
            &params);
        break;
    case SEC_HEADER:
        latest_section = new NHttpMsgHeader(data, dsize, session_data, source_id, buf_owner, flow,
            &params);
        break;
    case SEC_BODY:
        latest_section = new NHttpMsgBody(data, dsize, session_data, source_id, buf_owner, flow,
            &params);
        break;
    case SEC_CHUNK:
        latest_section = new NHttpMsgChunk(data, dsize, session_data, source_id, buf_owner, flow,
            &params);
        break;
    case SEC_TRAILER:
        latest_section = new NHttpMsgTrailer(data, dsize, session_data, source_id, buf_owner,
            flow, &params);
        break;
    default:
        assert(false);
        if (buf_owner)
        {
            delete[] data;
        }
        return false;
    }

    latest_section->analyze();
    latest_section->update_flow();
    latest_section->gen_events();

#ifdef REG_TEST
    if (NHttpTestManager::use_test_output())
    {
        latest_section->print_section(NHttpTestManager::get_output_file());
        fflush(NHttpTestManager::get_output_file());
        if (NHttpTestManager::use_test_input())
        {
            printf("Finished processing section from test %" PRIi64 "\n",
                NHttpTestManager::get_test_number());
        }
        fflush(stdout);
    }
#endif

    return latest_section->worth_detection();
}

void NHttpInspect::clear(Packet* p)
{
    latest_section = nullptr;

    NHttpFlowData* session_data =
        (NHttpFlowData*)p->flow->get_application_data(NHttpFlowData::nhttp_flow_id);

    if (session_data == nullptr)
        return;
    assert((p->packet_flags & PKT_FROM_CLIENT) || (p->packet_flags & PKT_FROM_SERVER));
    assert(!((p->packet_flags & PKT_FROM_CLIENT) && (p->packet_flags & PKT_FROM_SERVER)));
    SourceId source_id = (p->packet_flags & PKT_FROM_CLIENT) ? SRC_CLIENT : SRC_SERVER;

    if (session_data->transaction[source_id] == nullptr)
        return;

    clear(session_data, source_id);
}

void NHttpInspect::clear(NHttpFlowData* session_data, SourceId source_id)
{
    latest_section = nullptr;

    // If current transaction is complete then we are done with it and should reclaim the space
    if ((source_id == SRC_SERVER) && (session_data->type_expected[SRC_SERVER] == SEC_STATUS))
    {
        delete session_data->transaction[SRC_SERVER];
        session_data->transaction[SRC_SERVER] = nullptr;
    }
    else
    {
        // Get rid of most recent body section if present
        delete session_data->transaction[source_id]->get_body();
        session_data->transaction[source_id]->set_body(nullptr);
    }
}

