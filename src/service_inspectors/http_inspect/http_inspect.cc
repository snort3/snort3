//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/detection_engine.h"
#include "detection/detection_util.h"
#include "log/unified2.h"
#include "protocols/packet.h"
#include "stream/stream.h"

#include "http_js_norm.h"
#include "http_msg_body.h"
#include "http_msg_body_chunk.h"
#include "http_msg_body_cl.h"
#include "http_msg_body_old.h"
#include "http_msg_header.h"
#include "http_msg_request.h"
#include "http_msg_status.h"
#include "http_msg_trailer.h"
#include "http_test_manager.h"

using namespace snort;
using namespace HttpEnums;

uint32_t HttpInspect::xtra_trueip_id;
uint32_t HttpInspect::xtra_uri_id;
uint32_t HttpInspect::xtra_host_id;
uint32_t HttpInspect::xtra_jsnorm_id;

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

    xtra_trueip_id = Stream::reg_xtra_data_cb(get_xtra_trueip);
    xtra_uri_id = Stream::reg_xtra_data_cb(get_xtra_uri);
    xtra_host_id = Stream::reg_xtra_data_cb(get_xtra_host);
    xtra_jsnorm_id = Stream::reg_xtra_data_cb(get_xtra_jsnorm);

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

int HttpInspect::get_xtra_trueip(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    const HttpFlowData* const session_data =
        (HttpFlowData*)flow->get_flow_data(HttpFlowData::inspector_id);

    if ((session_data == nullptr) || (session_data->latest_section == nullptr))
        return 0;

    const HttpTransaction* const transaction = session_data->latest_section->get_transaction();
    HttpMsgHeader* const req_header = transaction->get_header(SRC_CLIENT);
    if (req_header == nullptr)
        return 0;
    const Field& true_ip = req_header->get_true_ip_addr();
    if (true_ip.length() <= 0)
        return 0;

    *buf = const_cast<uint8_t*>(true_ip.start());
    *len = true_ip.length();
    *type = (*len == 4) ? EVENT_INFO_XFF_IPV4 : EVENT_INFO_XFF_IPV6;
    return 1;
}

int HttpInspect::get_xtra_uri(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    const HttpFlowData* const session_data =
        (HttpFlowData*)flow->get_flow_data(HttpFlowData::inspector_id);

    if ((session_data == nullptr) || (session_data->latest_section == nullptr))
        return 0;

    const HttpTransaction* const transaction = session_data->latest_section->get_transaction();
    HttpMsgRequest* const request = transaction->get_request();
    if (request == nullptr)
        return 0;
    const Field& uri = request->get_uri();
    if (uri.length() <= 0)
        return 0;

    *buf = const_cast<uint8_t*>(uri.start());
    *len = uri.length();
    *type = EVENT_INFO_HTTP_URI;

    return 1;
}

int HttpInspect::get_xtra_host(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    const HttpFlowData* const session_data =
        (HttpFlowData*)flow->get_flow_data(HttpFlowData::inspector_id);

    if ((session_data == nullptr) || (session_data->latest_section == nullptr))
        return 0;

    const HttpTransaction* const transaction = session_data->latest_section->get_transaction();
    HttpMsgHeader* const req_header = transaction->get_header(SRC_CLIENT);
    if (req_header == nullptr)
        return 0;
    const Field& host = req_header->get_header_value_norm(HEAD_HOST);
    if (host.length() <= 0)
        return 0;

    *buf = const_cast<uint8_t*>(host.start());
    *len = host.length();
    *type = EVENT_INFO_HTTP_HOSTNAME;

    return 1;
}

// The name of this method reflects its legacy purpose. We actually return the normalized data
// from a response message body which may include other forms of normalization in addition to
// JavaScript normalization. But if you don't turn JavaScript normalization on you get nothing.
int HttpInspect::get_xtra_jsnorm(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    const HttpFlowData* const session_data =
        (HttpFlowData*)flow->get_flow_data(HttpFlowData::inspector_id);

    if ((session_data == nullptr) || (session_data->latest_section == nullptr) ||
        (session_data->latest_section->get_source_id() != SRC_SERVER) ||
        !session_data->latest_section->get_params()->js_norm_param.normalize_javascript)
        return 0;

    const HttpTransaction* const transaction = session_data->latest_section->get_transaction();
    HttpMsgBody* const body = transaction->get_body();
    if (body == nullptr)
        return 0;
    assert((void*)body == (void*)session_data->latest_section);
    const Field& detect_data = body->get_detect_data();
    if (detect_data.length() <= 0)
        return 0;

    *buf = const_cast<uint8_t*>(detect_data.start());
    *len = detect_data.length();
    *type = EVENT_INFO_JSNORM_DATA;

    return 1;
}

void HttpInspect::eval(Packet* p)
{
    Profile profile(HttpModule::get_profile_stats());

    const SourceId source_id = p->is_from_client() ? SRC_CLIENT : SRC_SERVER;

    HttpFlowData* session_data =
        (HttpFlowData*)p->flow->get_flow_data(HttpFlowData::inspector_id);

    // FIXIT-H Workaround for unexpected eval() calls
    if (session_data->section_type[source_id] == SEC__NOT_COMPUTE)
        return;

    // Limit alt_dsize of message body sections to request/response depth
    if ((session_data->detect_depth_remaining[source_id] > 0) &&
        (session_data->detect_depth_remaining[source_id] < p->dsize))
    {
        p->set_detect_limit(session_data->detect_depth_remaining[source_id]);
    }

    const int remove_workaround = session_data->zero_byte_workaround[source_id] ? 1 : 0;
    if (!process(p->data, p->dsize - remove_workaround, p->flow, source_id, true))
    {
        DetectionEngine::disable_content(p);
    }
#ifdef REG_TEST
    else
    {
        if (HttpTestManager::use_test_output())
        {
            fprintf(HttpTestManager::get_output_file(), "Sent to detection %hu octets\n\n",
                p->dsize);
            fflush(HttpTestManager::get_output_file());
        }
    }
#endif

    // Whenever we process a packet we set these flags. If someone asks for an extra data
    // buffer the JIT code will figure out if we actually have it.
    SetExtraData(p, xtra_trueip_id);
    SetExtraData(p, xtra_uri_id);
    SetExtraData(p, xtra_host_id);
    SetExtraData(p, xtra_jsnorm_id);
}

bool HttpInspect::process(const uint8_t* data, const uint16_t dsize, Flow* const flow,
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
        return false;
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
    return session_data->latest_section->detection_required();
}

void HttpInspect::clear(Packet* p)
{
    Profile profile(HttpModule::get_profile_stats());

    HttpFlowData* const session_data =
        (HttpFlowData*)p->flow->get_flow_data(HttpFlowData::inspector_id);

    if (session_data == nullptr)
        return;
    session_data->latest_section = nullptr;

    const SourceId source_id = (p->is_from_client()) ? SRC_CLIENT : SRC_SERVER;

    if (session_data->detection_status[source_id] == DET_DEACTIVATING)
    {
        if (source_id == SRC_CLIENT)
        {
            p->flow->set_to_server_detection(false);
        }
        else
        {
            p->flow->set_to_client_detection(false);
        }
        session_data->detection_status[source_id] = DET_OFF;
    }

    if (session_data->transaction[source_id] == nullptr)
        return;

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

