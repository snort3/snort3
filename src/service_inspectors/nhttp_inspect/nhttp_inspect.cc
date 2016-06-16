//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_types.h"
#include "stream/stream_api.h"

#include "nhttp_enum.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_status.h"
#include "nhttp_msg_header.h"
#include "nhttp_msg_body.h"
#include "nhttp_msg_body_chunk.h"
#include "nhttp_msg_body_cl.h"
#include "nhttp_msg_body_old.h"
#include "nhttp_msg_trailer.h"
#include "nhttp_test_manager.h"
#include "nhttp_field.h"

using namespace NHttpEnums;

NHttpInspect::NHttpInspect(const NHttpParaList* params_) : params(params_)
{
#ifdef REG_TEST
    if (params->test_input)
    {
        NHttpTestManager::activate_test_input();
    }
    if (params->test_output)
    {
        NHttpTestManager::activate_test_output();
    }
    NHttpTestManager::set_print_amount(params->print_amount);
    NHttpTestManager::set_print_hex(params->print_hex);
    NHttpTestManager::set_show_pegs(params->show_pegs);
#endif
}

THREAD_LOCAL uint8_t NHttpInspect::body_buffer[MAX_OCTETS];

SO_PUBLIC THREAD_LOCAL NHttpMsgSection* NHttpInspect::latest_section = nullptr;

NHttpEnums::InspectSection NHttpInspect::get_latest_is()
{
    return (latest_section != nullptr) ?
        latest_section->get_inspection_section() : NHttpEnums::IS_NONE;
}

bool NHttpInspect::get_buf(InspectionBuffer::Type ibt, Packet*, InspectionBuffer& b)
{
    switch (ibt)
    {
    case InspectionBuffer::IBT_KEY:
        return nhttp_get_buf(NHTTP_BUFFER_URI, 0, 0, nullptr, b);
    case InspectionBuffer::IBT_HEADER:
        if (get_latest_is() == IS_TRAILER)
            return nhttp_get_buf(NHTTP_BUFFER_TRAILER, 0, 0, nullptr, b);
        else
            return nhttp_get_buf(NHTTP_BUFFER_HEADER, 0, 0, nullptr, b);
    case InspectionBuffer::IBT_BODY:
        return nhttp_get_buf(NHTTP_BUFFER_CLIENT_BODY, 0, 0, nullptr, b);
    default:
        return false;
    }
}

SO_PUBLIC bool NHttpInspect::nhttp_get_buf(unsigned id, uint64_t sub_id, uint64_t form, Packet*,
    InspectionBuffer& b)
{
    if (latest_section == nullptr)
        return false;

    const Field& buffer = latest_section->get_classic_buffer(id, sub_id, form);

    if (buffer.length <= 0)
        return false;

    b.data = buffer.start;
    b.len = buffer.length;
    return true;
}

bool NHttpInspect::get_fp_buf(InspectionBuffer::Type ibt, Packet*, InspectionBuffer& b)
{
    // Fast pattern buffers only supplied at specific times
    switch (ibt)
    {
    case InspectionBuffer::IBT_KEY:
        if ((get_latest_is() != IS_DETECTION) || (get_latest_src() != SRC_CLIENT))
            return false;
        break;
    case InspectionBuffer::IBT_HEADER:
        if ((get_latest_is() != IS_DETECTION) && (get_latest_is() != IS_TRAILER))
            return false;
        break;
    case InspectionBuffer::IBT_BODY:
        if ((get_latest_is() != IS_DETECTION) && (get_latest_is() != IS_BODY))
            return false;
        break;
    default:
        return false;
    }
    return get_buf(ibt, nullptr, b);
}

const Field& NHttpInspect::process(const uint8_t* data, const uint16_t dsize, Flow* const flow,
    SourceId source_id, bool buf_owner) const
{
    NHttpFlowData* session_data = (NHttpFlowData*)flow->get_application_data(
        NHttpFlowData::nhttp_flow_id);
    assert(session_data != nullptr);

    NHttpModule::increment_peg_counts(PEG_INSPECT);

    switch (session_data->section_type[source_id])
    {
    case SEC_REQUEST:
        latest_section = new NHttpMsgRequest(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_STATUS:
        latest_section = new NHttpMsgStatus(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_HEADER:
        latest_section = new NHttpMsgHeader(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_BODY_CL:
        latest_section = new NHttpMsgBodyCl(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_BODY_OLD:
        latest_section = new NHttpMsgBodyOld(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_BODY_CHUNK:
        latest_section = new NHttpMsgBodyChunk(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_TRAILER:
        latest_section = new NHttpMsgTrailer(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    default:
        assert(false);
        if (buf_owner)
        {
            delete[] data;
        }
        return Field::FIELD_NULL;
    }

    latest_section->analyze();
    latest_section->update_flow();

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

    return latest_section->get_detect_buf();
}

void NHttpInspect::clear(Packet* p)
{
    latest_section = nullptr;

    NHttpFlowData* session_data =
        (NHttpFlowData*)p->flow->get_application_data(NHttpFlowData::nhttp_flow_id);

    if (session_data == nullptr)
        return;
    assert((p->is_from_client()) || (p->is_from_server()));
    assert(!((p->is_from_client()) && (p->is_from_server())));
    SourceId source_id = (p->is_from_client()) ? SRC_CLIENT : SRC_SERVER;

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

