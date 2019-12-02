//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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

#include <cassert>

#include "detection/detection_engine.h"
#include "detection/detection_util.h"
#include "log/unified2.h"
#include "protocols/packet.h"
#include "stream/stream.h"

#include "http_common.h"
#include "http_context_data.h"
#include "http_enum.h"
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
using namespace HttpCommon;
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
        HttpTestManager::activate_test_input(HttpTestManager::IN_HTTP);
    }
    if (params->test_output)
    {
        HttpTestManager::activate_test_output(HttpTestManager::IN_HTTP);
    }
    if ((params->test_input) || (params->test_output))
    {
        HttpTestManager::set_print_amount(params->print_amount);
        HttpTestManager::set_print_hex(params->print_hex);
        HttpTestManager::set_show_pegs(params->show_pegs);
        HttpTestManager::set_show_scan(params->show_scan);
    }
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

void HttpInspect::show(snort::SnortConfig*)
{
    assert(params);
    LogMessage("http_inspect\n");

    if ( params->request_depth == -1 )
        LogMessage("    request_depth: " "%s" "\n", "unlimited");
    else
        LogMessage("    request_depth: " STDi64 "\n", params->request_depth);

    if ( params->response_depth == -1 )
        LogMessage("    response_depth: " "%s" "\n", "unlimited");
    else
        LogMessage("    response_depth: " STDi64 "\n", params->response_depth);

    LogMessage("    unzip: %s\n", params->unzip ? "yes" : "no");
    LogMessage("    normalize_utf: %s\n", params->normalize_utf ? "yes" : "no");
    LogMessage("    decompress_pdf: %s\n", params->decompress_pdf ? "yes" : "no");
    LogMessage("    decompress_swf: %s\n", params->decompress_swf ? "yes" : "no");
    LogMessage("    decompress_zip: %s\n", params->decompress_zip ? "yes" : "no");
    LogMessage("    detained_inspection: %s\n", params->detained_inspection ? "yes" : "no");

    LogMessage("    normalize_javascript: %s\n", params->js_norm_param.normalize_javascript ? "yes" : "no");
    LogMessage("    max_javascript_whitespaces: %d\n", params->js_norm_param.max_javascript_whitespaces);

    LogMessage("    percent_u: %s\n", params->uri_param.percent_u ? "yes" : "no");
    LogMessage("    utf8: %s\n", params->uri_param.utf8 ? "yes" : "no");
    LogMessage("    utf8_bare_byte: %s\n", params->uri_param.utf8_bare_byte ? "yes" : "no");
    LogMessage("    oversize_dir_length: %d\n", params->uri_param.oversize_dir_length);
    LogMessage("    iis_unicode: %s\n", params->uri_param.iis_unicode ? "yes" : "no");
    LogMessage("    iis_unicode_map_file: %s\n", params->uri_param.iis_unicode_map_file.c_str());
    LogMessage("    iis_double_decode: %s\n", params->uri_param.iis_double_decode ? "yes" : "no");
    LogMessage("    backslash_to_slash: %s\n", params->uri_param.backslash_to_slash ? "yes" : "no");
    LogMessage("    plus_to_space: %s\n", params->uri_param.plus_to_space ? "yes" : "no");
    LogMessage("    simplify_path: %s\n", params->uri_param.simplify_path ? "yes" : "no");
}

InspectSection HttpInspect::get_latest_is(const Packet* p)
{
    HttpMsgSection* current_section = HttpContextData::get_snapshot(p);

    if (current_section == nullptr)
        return IS_NONE;

    // FIXIT-L revisit why we need this check. We should not be getting a current section back
    // for a raw packet but one of the test cases did exactly that.
    if (!(p->packet_flags & PKT_PSEUDO))
        return IS_NONE;

    return current_section->get_inspection_section();
}

SourceId HttpInspect::get_latest_src(const Packet* p)
{
    HttpMsgSection* current_section = HttpContextData::get_snapshot(p);

    if (current_section == nullptr)
        return SRC__NOT_COMPUTE;

    return current_section->get_source_id();
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
    HttpMsgSection* current_section = HttpContextData::get_snapshot(p);

    if (current_section == nullptr)
        return false;

    const Field& buffer = current_section->get_classic_buffer(id, sub_id, form);

    if (buffer.length() <= 0)
        return false;

    b.data = buffer.start();
    b.len = buffer.length();
    return true;
}

bool HttpInspect::get_fp_buf(InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    if (get_latest_is(p) == IS_NONE)
        return false;

    // Fast pattern buffers only supplied at specific times
    switch (ibt)
    {
    case InspectionBuffer::IBT_KEY:
        // Many rules targeting POST feature http_uri fast pattern with http_client_body. We
        // accept the performance hit of rerunning http_uri fast pattern with request body message
        // sections
        if (get_latest_src(p) != SRC_CLIENT)
            return false;
        break;
    case InspectionBuffer::IBT_HEADER:
        // http_header fast patterns for response bodies limited to first section
        if ((get_latest_src(p) == SRC_SERVER) && (get_latest_is(p) == IS_BODY))
            return false;
        break;
    case InspectionBuffer::IBT_BODY:
        if ((get_latest_is(p) != IS_FIRST_BODY) && (get_latest_is(p) != IS_BODY))
            return false;
        break;
    default:
        return false;
    }
    return get_buf(ibt, p, b);
}

int HttpInspect::get_xtra_trueip(Flow*, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    HttpMsgSection* current_section = HttpContextData::get_snapshot(nullptr);

    if (current_section == nullptr)
        return 0;

    HttpMsgHeader* const req_header = current_section->get_header(SRC_CLIENT);
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

int HttpInspect::get_xtra_uri(Flow*, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    HttpMsgSection* current_section = HttpContextData::get_snapshot(nullptr);

    if (current_section == nullptr)
        return 0;

    HttpMsgRequest* const request = current_section->get_request();
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

int HttpInspect::get_xtra_host(Flow*, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    HttpMsgSection* current_section = HttpContextData::get_snapshot(nullptr);

    if (current_section == nullptr)
        return 0;

    HttpMsgHeader* const req_header = current_section->get_header(SRC_CLIENT);
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
int HttpInspect::get_xtra_jsnorm(Flow*, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    HttpMsgSection* current_section = HttpContextData::get_snapshot(nullptr);

    if ((current_section == nullptr) ||
        (current_section->get_source_id() != SRC_SERVER) ||
        !current_section->get_params()->js_norm_param.normalize_javascript)
        return 0;

    HttpMsgBody* const body = current_section->get_body();
    if (body == nullptr)
        return 0;
    assert((void*)body == (void*)current_section);
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

    // Don't make pkt_data for headers available to detection
    if ((session_data->section_type[source_id] == SEC_HEADER) ||
        (session_data->section_type[source_id] == SEC_TRAILER))
    {
        p->set_detect_limit(0);
    }

    // Limit alt_dsize of message body sections to request/response depth
    if ((session_data->detect_depth_remaining[source_id] > 0) &&
        (session_data->detect_depth_remaining[source_id] < p->dsize))
    {
        p->set_detect_limit(session_data->detect_depth_remaining[source_id]);
    }

    const bool buf_owner = !session_data->partial_flush[source_id];
    if (!process(p->data, p->dsize, p->flow, source_id, buf_owner))
    {
        DetectionEngine::disable_content(p);
    }

#ifdef REG_TEST
    else
    {
        if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP))
        {
            fprintf(HttpTestManager::get_output_file(), "Sent to detection %hu octets\n\n",
                p->dsize);
            fflush(HttpTestManager::get_output_file());
        }
    }
#endif

    // If current transaction is complete then we are done with it. This is strictly a memory
    // optimization not necessary for correct operation.
    if ((source_id == SRC_SERVER) && (session_data->type_expected[SRC_SERVER] == SEC_STATUS) &&
         session_data->transaction[SRC_SERVER]->final_response())
    {
        HttpTransaction::delete_transaction(session_data->transaction[SRC_SERVER], session_data);
        session_data->transaction[SRC_SERVER] = nullptr;
    }

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
    HttpMsgSection* current_section;
    HttpFlowData* session_data = (HttpFlowData*)flow->get_flow_data(HttpFlowData::inspector_id);
    assert(session_data != nullptr);

    if (!session_data->partial_flush[source_id])
        HttpModule::increment_peg_counts(PEG_INSPECT);
    else
        HttpModule::increment_peg_counts(PEG_PARTIAL_INSPECT);

    switch (session_data->section_type[source_id])
    {
    case SEC_REQUEST:
        current_section = new HttpMsgRequest(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_STATUS:
        current_section = new HttpMsgStatus(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_HEADER:
        current_section = new HttpMsgHeader(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_BODY_CL:
        current_section = new HttpMsgBodyCl(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_BODY_OLD:
        current_section = new HttpMsgBodyOld(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_BODY_CHUNK:
        current_section = new HttpMsgBodyChunk(
            data, dsize, session_data, source_id, buf_owner, flow, params);
        break;
    case SEC_TRAILER:
        current_section = new HttpMsgTrailer(
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

    current_section->analyze();
    current_section->gen_events();
    if (!session_data->partial_flush[source_id])
        current_section->update_flow();
    session_data->partial_flush[source_id] = false;
    session_data->section_type[source_id] = SEC__NOT_COMPUTE;

#ifdef REG_TEST
    if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP))
    {
        current_section->print_section(HttpTestManager::get_output_file());
        fflush(HttpTestManager::get_output_file());
        if (HttpTestManager::use_test_input(HttpTestManager::IN_HTTP))
        {
            printf("Finished processing section from test %" PRIi64 "\n",
                HttpTestManager::get_test_number());
        }
        fflush(stdout);
    }
#endif

    current_section->publish();
    return current_section->detection_required();
}

void HttpInspect::clear(Packet* p)
{
    Profile profile(HttpModule::get_profile_stats());

    HttpFlowData* const session_data =
        (HttpFlowData*)p->flow->get_flow_data(HttpFlowData::inspector_id);

    if ( session_data == nullptr )
        return;

    HttpMsgSection* current_section = HttpContextData::clear_snapshot(p->context);

    // FIXIT-M This test is necessary because sometimes we get extra clears
    // Convert to assert when that gets fixed.
    if ( current_section == nullptr )
        return;

    current_section->clear();
    HttpTransaction* current_transaction = current_section->get_transaction();

    const SourceId source_id = current_section->get_source_id();

    //FIXIT-M This check may not apply to the transaction attached to the packet
    //in case of offload. 
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

    current_transaction->garbage_collect();
    session_data->garbage_collect();
}

