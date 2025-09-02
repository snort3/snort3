//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
#include <iomanip>
#include <sstream>

#include "detection/detection_engine.h"
#include "service_inspectors/http2_inspect/http2_flow_data.h"
#include "log/unified2.h"
#include "protocols/packet.h"
#include "pub_sub/http_event_ids.h"
#include "stream/stream.h"

#include "http_common.h"
#include "http_context_data.h"
#include "http_enum.h"
#include "http_js_norm.h"
#include "http_msg_body.h"
#include "http_msg_body_chunk.h"
#include "http_msg_body_cl.h"
#include "http_msg_body_hx.h"
#include "http_msg_body_old.h"
#include "http_msg_header.h"
#include "http_msg_request.h"
#include "http_msg_status.h"
#include "http_msg_trailer.h"
#include "http_param.h"
#include "http_test_manager.h"

using namespace snort;
using namespace HttpCommon;
using namespace HttpEnums;

static std::string GetUnreservedChars(const ByteBitSet& bitset)
{
    const ByteBitSet& def_bitset(HttpParaList::UriParam::UriParam::default_unreserved_char);
    std::string chars;

    for (unsigned char c = 1; c; ++c)
        if (def_bitset[c] && !bitset[c])
            chars += c;

    return chars;
}

static std::string GetBadChars(const ByteBitSet& bitset)
{
    std::stringstream ss;
    ss << std::hex;

    for (unsigned i = 0; i < bitset.size(); ++i)
        if (bitset[i])
            ss << " 0x" << std::setw(2) << std::setfill('0') << i;

    auto str = ss.str();
    if ( !str.empty() )
        str.erase(0, 1);

    return str;
}


static std::string GetXFFHeaders(const StrCode *header_list)
{
    std::string hdr_list;
    for (int idx = 0; header_list[idx].code; idx++)
    {
        hdr_list += header_list[idx].name;
        hdr_list += " ";
    }

    // Remove the trailing whitespace, if any
    if (hdr_list.length())
    {
        hdr_list.pop_back();
    }
    return hdr_list;
}

HttpInspect::HttpInspect(const HttpParaList* params_) :
    params(params_),
    xtra_trueip_id(Stream::reg_xtra_data_cb(get_xtra_trueip)),
    xtra_uri_id(Stream::reg_xtra_data_cb(get_xtra_uri)),
    xtra_host_id(Stream::reg_xtra_data_cb(get_xtra_host)),
    xtra_jsnorm_id(Stream::reg_xtra_data_cb(get_xtra_jsnorm))
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

    HttpTestManager::set_print_amount(params->print_amount);
    HttpTestManager::set_print_hex(params->print_hex);
    HttpTestManager::set_show_pegs(params->show_pegs);
    HttpTestManager::set_show_scan(params->show_scan);

#endif

    if (params->script_detection)
    {
        script_finder = new ScriptFinder(params->script_detection_handle);
    }
}

HttpInspect::~HttpInspect()
{
    delete params->mime_decode_conf;
    delete params;
    delete script_finder;
}

bool HttpInspect::configure(SnortConfig* sc)
{
    params->js_norm_param.configure();
    params->mime_decode_conf->sync_all_depths(sc);

    if (!pub_id)
        pub_id = DataBus::get_id(http_pub_key);

    return true;
}

void HttpInspect::show(const SnortConfig*) const
{
    assert(params);

    auto unreserved_chars = GetUnreservedChars(params->uri_param.unreserved_char);
    auto bad_chars = GetBadChars(params->uri_param.bad_characters);
    auto xff_headers = GetXFFHeaders(params->xff_headers);

    ConfigLogger::log_limit("request_depth", params->request_depth, -1);
    ConfigLogger::log_limit("response_depth", params->response_depth, -1);
    ConfigLogger::log_limit("partial_depth_header", params->partial_depth_header, -1, 0);
    ConfigLogger::log_limit("partial_depth_body", params->partial_depth_body, -1, 0);
    ConfigLogger::log_flag("unzip", params->unzip);
    ConfigLogger::log_flag("normalize_utf", params->normalize_utf);
    ConfigLogger::log_flag("decompress_pdf", params->decompress_pdf);
    ConfigLogger::log_flag("decompress_swf", params->decompress_swf);
    ConfigLogger::log_flag("decompress_zip", params->decompress_zip);
    ConfigLogger::log_flag("decompress_vba", params->decompress_vba);
    ConfigLogger::log_value("max_mime_attach", params->max_mime_attach);
    ConfigLogger::log_flag("script_detection", params->script_detection);
    ConfigLogger::log_flag("normalize_javascript", params->js_norm_param.normalize_javascript);
    ConfigLogger::log_value("max_javascript_whitespaces",
        params->js_norm_param.max_javascript_whitespaces);
    ConfigLogger::log_value("bad_characters", bad_chars.c_str());
    ConfigLogger::log_value("ignore_unreserved", unreserved_chars.c_str());
    ConfigLogger::log_flag("percent_u", params->uri_param.percent_u);
    ConfigLogger::log_flag("utf8", params->uri_param.utf8);
    ConfigLogger::log_flag("utf8_bare_byte", params->uri_param.utf8_bare_byte);
    ConfigLogger::log_flag("iis_unicode", params->uri_param.iis_unicode);
    ConfigLogger::log_value("iis_unicode_map_file", params->uri_param.iis_unicode_map_file.c_str());
    ConfigLogger::log_value("iis_unicode_code_page", params->uri_param.iis_unicode_code_page);
    ConfigLogger::log_flag("iis_double_decode", params->uri_param.iis_double_decode);
    ConfigLogger::log_value("oversize_dir_length", params->uri_param.oversize_dir_length);
    ConfigLogger::log_flag("backslash_to_slash", params->uri_param.backslash_to_slash);
    ConfigLogger::log_flag("plus_to_space", params->uri_param.plus_to_space);
    ConfigLogger::log_flag("simplify_path", params->uri_param.simplify_path);
    ConfigLogger::log_value("xff_headers", xff_headers.c_str());
    ConfigLogger::log_flag("request_body_app_detection", params->publish_request_body);
}

PduSection HttpInspect::get_latest_is(const Packet* p)
{
    HttpMsgSection* current_section = HttpContextData::get_snapshot(p);

    if (current_section == nullptr)
        return PS_NONE;

    // FIXIT-L revisit why we need this check. We should not be getting a current section back
    // for a raw packet but one of the test cases did exactly that.
    if (!(p->packet_flags & PKT_PSEUDO))
        return PS_NONE;

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
        return get_buf(HTTP_BUFFER_URI, p, b);

    case InspectionBuffer::IBT_HEADER:
        if (get_latest_is(p) == PS_TRAILER)
            return get_buf(HTTP_BUFFER_TRAILER, p, b);
        else
            return get_buf(HTTP_BUFFER_HEADER, p , b);

    case InspectionBuffer::IBT_BODY:
        return get_buf(HTTP_BUFFER_CLIENT_BODY, p, b);

    case InspectionBuffer::IBT_VBA:
        return get_buf(BUFFER_VBA_DATA, p, b);

    case InspectionBuffer::IBT_JS_DATA:
        return get_buf(BUFFER_JS_DATA, p, b);

    default:
        assert(false);
        return false;
    }
}

bool HttpInspect::get_buf(unsigned id, Packet* p, InspectionBuffer& b)
{
    HttpBufferInfo buffer_info(id);

    const Field& http_buffer = http_get_buf(p, buffer_info);

    if (http_buffer.length() <= 0)
        return false;

    b.data = http_buffer.start();
    b.len = http_buffer.length();
    b.is_accumulated = http_buffer.is_accumulated();

    return true;
}

const Field& HttpInspect::http_get_buf(Packet* p, const HttpBufferInfo& buffer_info) const
{
    HttpMsgSection* const current_section = HttpContextData::get_snapshot(p);

    if (current_section == nullptr)
        return Field::FIELD_NULL;

    return current_section->get_classic_buffer(buffer_info);
}

const Field& HttpInspect::http_get_param_buf(Cursor& c, Packet* p,
    const HttpParam& param) const
{
    HttpMsgSection* const current_section = HttpContextData::get_snapshot(p);

    if (current_section == nullptr)
        return Field::FIELD_NULL;

    return current_section->get_param_buffer(c, param);
}

int32_t HttpInspect::http_get_num_headers(Packet* p,
    const HttpBufferInfo& buffer_info) const
{
    const HttpMsgSection* const current_section = HttpContextData::get_snapshot(p);

    if (current_section == nullptr)
        return STAT_NOT_PRESENT;

    return current_section->get_num_headers(buffer_info);
}

int32_t HttpInspect::http_get_max_header_line(Packet* p,
    const HttpBufferInfo& buffer_info) const
{
    const HttpMsgSection* const current_section = HttpContextData::get_snapshot(p);

    if (current_section == nullptr)
        return STAT_NOT_PRESENT;

    return current_section->get_max_header_line(buffer_info);
}

int32_t HttpInspect::http_get_num_cookies(Packet* p,
    const HttpBufferInfo& buffer_info) const
{
    const HttpMsgSection* const current_section = HttpContextData::get_snapshot(p);

    if (current_section == nullptr)
        return STAT_NOT_PRESENT;

    return current_section->get_num_cookies(buffer_info);
}

VersionId HttpInspect::http_get_version_id(Packet* p,
    const HttpBufferInfo& buffer_info) const
{
    const HttpMsgSection* const current_section = HttpContextData::get_snapshot(p);

    if (current_section == nullptr)
        return VERS__NOT_PRESENT;

    return current_section->get_version_id(buffer_info);
}

HttpCommon::SectionType HttpInspect::get_type_expected(snort::Flow* flow, HttpCommon::SourceId source_id) const
{
    HttpFlowData* session_data = http_get_flow_data(flow);
    return session_data->get_type_expected(source_id);
}

void HttpInspect::finish_hx_body(snort::Flow* flow, HttpCommon::SourceId source_id, HttpCommon::HXBodyState state,
    bool clear_partial_buffer) const
{
    HttpFlowData* session_data = http_get_flow_data(flow);
    session_data->finish_hx_body(source_id, state, clear_partial_buffer);
}

void HttpInspect::set_hx_body_state(snort::Flow* flow, HttpCommon::SourceId source_id, HttpCommon::HXBodyState state) const
{
    HttpFlowData* session_data = http_get_flow_data(flow);
    session_data->set_hx_body_state(source_id, state);
}

bool HttpInspect::get_fp_buf(InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    assert(ibt == InspectionBuffer::IBT_VBA or ibt == InspectionBuffer::IBT_JS_DATA);

    if (get_latest_is(p) == PS_NONE)
        return false;

    return get_buf(ibt, p, b);
}

int HttpInspect::get_xtra_trueip(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    HttpMsgSection* current_section = HttpContextData::get_snapshot(flow);

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

int HttpInspect::get_xtra_uri(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    HttpMsgSection* current_section = HttpContextData::get_snapshot(flow);

    if (current_section == nullptr)
        return 0;

    HttpMsgRequest* const request = current_section->get_request();
    if (request == nullptr)
        return 0;
    const Field& uri = request->get_uri_norm_classic();
    if (uri.length() <= 0)
        return 0;

    *buf = const_cast<uint8_t*>(uri.start());
    *len = uri.length();
    *type = EVENT_INFO_HTTP_URI;

    return 1;
}

int HttpInspect::get_xtra_host(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    HttpMsgSection* current_section = HttpContextData::get_snapshot(flow);

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
int HttpInspect::get_xtra_jsnorm(Flow* flow, uint8_t** buf, uint32_t* len, uint32_t* type)
{
    HttpMsgSection* current_section = HttpContextData::get_snapshot(flow);

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

void HttpInspect::disable_detection(Packet* p)
{
    HttpFlowData* session_data = http_get_flow_data(p->flow);
    if (!session_data->for_httpx)
    {
        assert(p->context);
        DetectionEngine::disable_all(p);
    }
}

HttpFlowData* HttpInspect::http_get_flow_data(const Flow* flow)
{
    if (flow->stream_intf)
        return (HttpFlowData*)flow->stream_intf->get_stream_flow_data(flow);
    else
        return (HttpFlowData*)flow->get_flow_data(HttpFlowData::inspector_id);
}

void HttpInspect::http_set_flow_data(Flow* flow, HttpFlowData* flow_data)
{
    if (flow->stream_intf)
        flow->stream_intf->set_stream_flow_data(flow, flow_data);
    else
        flow->set_flow_data(flow_data);
}

void HttpInspect::eval(Packet* p)
{
    const SourceId source_id = p->is_from_client() ? SRC_CLIENT : SRC_SERVER;
    eval(p, source_id, p->data, p->dsize);
    return;
}

void HttpInspect::eval(Packet* p, SourceId source_id, const uint8_t* data, uint16_t dsize)
{
    // cppcheck-suppress unreadVariable
    Profile profile(HttpModule::get_profile_stats());

    HttpFlowData* session_data = http_get_flow_data(p->flow);
    if (session_data == nullptr)
    {
        assert(false);
        return;
    }

    // FIXIT-M Workaround for unexpected eval() calls. Currently asserting when stream_user is in
    // use due to calls to HttpInspect::eval on the raw stream_user packet
    if ((session_data->section_type[source_id] == SEC__NOT_COMPUTE) ||
        (session_data->type_expected[source_id] == SEC_ABORT)       ||
        (session_data->octets_reassembled[source_id] != dsize))
    {
        //assert(session_data->type_expected[source_id] != SEC_ABORT);
        //assert(session_data->section_type[source_id] != SEC__NOT_COMPUTE);
        //assert(session_data->octets_reassembled[source_id] == dsize);
        session_data->type_expected[source_id] = SEC_ABORT;
        return;
    }

    if (!session_data->for_httpx)
        HttpModule::increment_peg_counts(PEG_TOTAL_BYTES, dsize);

    session_data->octets_reassembled[source_id] = STAT_NOT_PRESENT;

    // Don't make pkt_data for headers, request and response available to detection
    if ((session_data->section_type[source_id] == SEC_HEADER) ||
        (session_data->section_type[source_id] == SEC_TRAILER) ||
        (session_data->section_type[source_id] == SEC_REQUEST) ||
        (session_data->section_type[source_id] == SEC_STATUS))
    {
        p->set_detect_limit(0);
    }

    // Limit alt_dsize of message body sections to request/response depth
    // p->dsize is not a typo. The actual value on the reassembled packet is what matters for this purpose.
    if ((session_data->detect_depth_remaining[source_id] > 0) &&
        (session_data->detect_depth_remaining[source_id] < p->dsize))
    {
        p->set_detect_limit(session_data->detect_depth_remaining[source_id]);
    }

    process(data, dsize, p->flow, source_id, true, p);

    // Detection was done in process()
    if (!session_data->for_httpx)
        disable_detection(p);

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

void HttpInspect::process(const uint8_t* data, const uint16_t dsize, Flow* const flow, SourceId source_id,
    bool buf_owner, Packet* p) const
{
    HttpMsgSection* current_section;
    HttpFlowData* session_data = http_get_flow_data(flow);

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
    case SEC_BODY_HX:
        current_section = new HttpMsgBodyHX(
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
        return;
    }

    current_section->analyze();
    current_section->gen_events();
    if (!session_data->partial_flush[source_id])
        current_section->update_flow();
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

    current_section->publish(pub_id);
    if (p != nullptr)
    {
        const PduSection pdu_section = current_section->get_inspection_section();
        p->set_pdu_section(pdu_section);
    }

    if (current_section->run_detection(p))
    {
#ifdef REG_TEST
        if (HttpTestManager::use_test_output(HttpTestManager::IN_HTTP))
        {
            fprintf(HttpTestManager::get_output_file(), "Sent to detection %hu octets\n\n",
                dsize);
            fflush(HttpTestManager::get_output_file());
        }
#endif
    }
}

void HttpInspect::clear(Packet* p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(HttpModule::get_profile_stats());

    HttpFlowData* const session_data = http_get_flow_data(p->flow);

    if (session_data == nullptr)
    {
        assert(false);
        return;
    }

    HttpMsgSection* current_section = nullptr;
    if(p->flow->stream_intf)
    {
        current_section = (HttpMsgSection*)p->flow->stream_intf->get_hi_msg_section(p->flow);
        assert(current_section != nullptr);
        p->flow->stream_intf->set_hi_msg_section(p->flow, nullptr);
    }
    else
        current_section = HttpContextData::clear_snapshot(p->context);

    if ( current_section == nullptr )
    {
        //assert(false); //FIXIT-M This happens with stream_user
        return;
    }

    current_section->clear();
    HttpTransaction* current_transaction = current_section->get_transaction();

    current_transaction->garbage_collect();
    session_data->garbage_collect();

    if (session_data->cutover_on_clear)
    {
        Flow* flow = p->flow;
        flow->set_service(p, nullptr);
        flow->free_flow_data(HttpFlowData::inspector_id);
    }
}

const uint8_t* HttpInspect::adjust_log_packet(Packet* p, uint16_t& length)
{
    HttpMsgSection*  current_section = HttpContextData::get_snapshot(p);
    if (current_section == nullptr ||
        current_section->get_inspection_section() != PS_HEADER)
        return nullptr;

    HttpMsgSection* other_section = nullptr;
    unsigned id;
    if ((HttpMsgHeader*)current_section == current_section->get_header(SRC_CLIENT))
    {
        other_section = current_section->get_request();
        id = HTTP_BUFFER_RAW_REQUEST;
    }
    else if ((HttpMsgHeader*)current_section == current_section->get_header(SRC_SERVER))
    {
        other_section = current_section->get_status();
        id = HTTP_BUFFER_RAW_STATUS;
    }
    else
        return nullptr;

    assert(other_section != nullptr);
    if (other_section == nullptr)
        return nullptr;

    const Field& start_line = other_section->get_classic_buffer(id, 0, 0);
    if (start_line.length() > 0)
    {
        static const uint8_t END_HEADERS[] = "\r\n\r\n";
        static const size_t END_HEADERS_LEN = 4;
        static const uint8_t* END_START_LINE = END_HEADERS;
        static const size_t END_START_LINE_LEN = 2;

        const struct { const uint8_t* data; const size_t len; } frags[] =
        {
            { start_line.start(), (size_t) start_line.length() },
            { END_START_LINE, END_START_LINE_LEN },
            { p->data, p->dsize },
            { END_HEADERS, END_HEADERS_LEN }
        };
        const uint frags_cnt = sizeof(frags)/sizeof(frags[0]);

        uint8_t* data = new uint8_t[start_line.length() + END_START_LINE_LEN +
                                    p->dsize + END_HEADERS_LEN];

        uint8_t* dst = data;
        for (uint i = 0; i < frags_cnt; i++)
        {
            memcpy(dst, frags[i].data, frags[i].len);
            dst += frags[i].len;
        }

        length = dst - data;
        return data;
    }

    return nullptr;
}
