//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// http_inspect.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_inspect.h"

#include "protocols/packet.h"

#include "http_msg_body.h"
#include "http_msg_body_chunk.h"
#include "http_msg_body_cl.h"
#include "http_msg_body_old.h"
#include "http_msg_header.h"
#include "http_msg_request.h"
#include "http_msg_status.h"
#include "http_msg_trailer.h"
#include "http_js_norm.h"

using namespace HttpEnums;

HttpInspect::HttpInspect(const HttpParaList* params_) : params(params_)
{
#ifdef REG_TEST
    if (params->test_input)
    {
        HttpTestManager::activate_test_input();
    }
    if (params->test_output)
    {
        HttpTestManager::activate_test_output();
    }
    HttpTestManager::set_print_amount(params->print_amount);
    HttpTestManager::set_print_hex(params->print_hex);
    HttpTestManager::set_show_pegs(params->show_pegs);
    HttpTestManager::set_show_scan(params->show_scan);
#endif
}

bool HttpInspect::configure(SnortConfig* )
{
    if (params->js_norm_param.normalize_javascript)
        params->js_norm_param.js_norm->configure();
    return true;
}

InspectSection HttpInspect::get_latest_is(const Packet* p)
{
    const HttpFlowData* const session_data =
        (HttpFlowData*)p->flow->get_flow_data(HttpFlowData::inspector_id);

    if ((session_data == nullptr) || (session_data->latest_section == nullptr))
        return HttpEnums::IS_NONE;

    return session_data->latest_section->get_inspection_section();
}

SourceId HttpInspect::get_latest_src(const Packet* p)
{
    const HttpFlowData* const session_data =
        (HttpFlowData*)p->flow->get_flow_data(HttpFlowData::inspector_id);

    if ((session_data == nullptr) || (session_data->latest_section == nullptr))
        return HttpEnums::SRC__NOT_COMPUTE;

    return session_data->latest_section->get_source_id();
}

bool HttpInspect::get_buf(InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    switch (ibt)
    {
    case InspectionBuffer::IBT_KEY:
        return http_get_buf(HTTP_BUFFER_URI, 0, 0, p, b);
    case InspectionBuffer::IBT_HEADER:
        if (get_latest_is(p) == IS_TRAILER)
            return http_get_buf(HTTP_BUFFER_TRAILER, 0, 0, p, b);
        else
            return http_get_buf(HTTP_BUFFER_HEADER, 0, 0, p, b);
    case InspectionBuffer::IBT_BODY:
        return http_get_buf(HTTP_BUFFER_CLIENT_BODY, 0, 0, p, b);
    default:
        return false;
    }
}

bool HttpInspect::get_buf(unsigned id, Packet* p, InspectionBuffer& b)
{
    return http_get_buf(id, 0, 0, p, b);
}

bool HttpInspect::http_get_buf(unsigned id, uint64_t sub_id, uint64_t form, Packet* p,
    InspectionBuffer& b)
{
    const HttpFlowData* const session_data =
        (HttpFlowData*)p->flow->get_flow_data(HttpFlowData::inspector_id);

    if ((session_data == nullptr) || (session_data->latest_section == nullptr))
        return false;

    const Field& buffer = session_data->latest_section->get_classic_buffer(id, sub_id, form);

    if (buffer.length() <= 0)
        return false;

    b.data = buffer.start();
    b.len = buffer.length();
    return true;
}

bool HttpInspect::get_fp_buf(InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    // Fast pattern buffers only supplied at specific times
    switch (ibt)
    {
    case InspectionBuffer::IBT_KEY:
        if ((get_latest_is(p) != IS_DETECTION) || (get_latest_src(p) != SRC_CLIENT))
            return false;
        break;
    case InspectionBuffer::IBT_HEADER:
        if ((get_latest_is(p) != IS_DETECTION) && (get_latest_is(p) != IS_TRAILER))
            return false;
        break;
    case InspectionBuffer::IBT_BODY:
        if ((get_latest_is(p) != IS_DETECTION) && (get_latest_is(p) != IS_BODY))
            return false;
        break;
    default:
        return false;
    }
    return get_buf(ibt, p, b);
}

const Field& HttpInspect::process(const uint8_t* data, const uint16_t dsize, Flow* const flow,
    SourceId source_id, bool buf_owner) const
{
    HttpFlowData* session_data = (HttpFlowData*)flow->get_flow_data(HttpFlowData::inspector_id);
    assert(session_data != nullptr);

    HttpModule::increment_peg_counts(PEG_INSPECT);

    switch (session_data->section_type[source_id])
    {
    case SEC_REQUEST:
        session_data->latest_section = new HttpMsgRequest(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_STATUS:
        session_data->latest_section = new HttpMsgStatus(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_HEADER:
        session_data->latest_section = new HttpMsgHeader(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_BODY_CL:
        session_data->latest_section = new HttpMsgBodyCl(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_BODY_OLD:
        session_data->latest_section = new HttpMsgBodyOld(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_BODY_CHUNK:
        session_data->latest_section = new HttpMsgBodyChunk(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_TRAILER:
        session_data->latest_section = new HttpMsgTrailer(
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

    session_data->latest_section->analyze();
    session_data->latest_section->gen_events();
    session_data->latest_section->update_flow();

#ifdef REG_TEST
    if (HttpTestManager::use_test_output())
    {
        session_data->latest_section->print_section(HttpTestManager::get_output_file());
        fflush(HttpTestManager::get_output_file());
        if (HttpTestManager::use_test_input())
        {
            printf("Finished processing section from test %" PRIi64 "\n",
                HttpTestManager::get_test_number());
        }
        fflush(stdout);
    }
#endif

    session_data->latest_section->publish();
    return session_data->latest_section->get_detect_buf();
}

void HttpInspect::clear(Packet* p)
{
    HttpFlowData* session_data =
        (HttpFlowData*)p->flow->get_flow_data(HttpFlowData::inspector_id);

    if (session_data == nullptr)
        return;
    session_data->latest_section = nullptr;

    assert((p->is_from_client()) || (p->is_from_server()));
    assert(!((p->is_from_client()) && (p->is_from_server())));
    SourceId source_id = (p->is_from_client()) ? SRC_CLIENT : SRC_SERVER;

    if (session_data->transaction[source_id] == nullptr)
        return;

    clear(session_data, source_id);
}

void HttpInspect::clear(HttpFlowData* session_data, SourceId source_id)
{
    session_data->latest_section = nullptr;

    // If current transaction is complete then we are done with it and should reclaim the space
    if ((source_id == SRC_SERVER) && (session_data->type_expected[SRC_SERVER] == SEC_STATUS) &&
         session_data->transaction[SRC_SERVER]->final_response())
    {
        HttpTransaction::delete_transaction(session_data->transaction[SRC_SERVER]);
        session_data->transaction[SRC_SERVER] = nullptr;
    }
    else
    {
        // Get rid of most recent body section if present
        session_data->transaction[source_id]->set_body(nullptr);
    }
}

