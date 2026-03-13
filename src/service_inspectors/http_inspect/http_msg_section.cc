//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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
// http_msg_section.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_section.h"

#include "service_inspectors/http2_inspect/http2_flow_data.h"

#include "http_context_data.h"
#include "http_common.h"
#include "http_compress_stream.h"
#include "http_enum.h"
#include "http_module.h"
#include "http_msg_body.h"
#include "http_msg_head_shared.h"
#include "http_msg_header.h"
#include "http_msg_request.h"
#include "http_msg_status.h"
#include "http_msg_trailer.h"
#include "http_param.h"
#include "http_query_parser.h"
#include "http_test_manager.h"
#include "stream/flush_bucket.h"

using namespace HttpCommon;
using namespace HttpEnums;
using namespace snort;

static constexpr uint TMP_BUFFER_CNT = HTTP__TMP_BUFFER_MAX - HTTP__BUFFER_MAX;
THREAD_LOCAL Field* tmp_buffers[TMP_BUFFER_CNT] = { nullptr };
THREAD_LOCAL Field* decoded_path = nullptr;

void HttpMsgSection::clear_tmp_buffers()
{
    for (unsigned i = 0; i < TMP_BUFFER_CNT; i++)
    {
        delete tmp_buffers[i];
        tmp_buffers[i] = nullptr;
    }
    delete decoded_path;
    decoded_path = nullptr;
}

static Field* tmp_field_from_data(const uint8_t* data, uint32_t len)
{
    uint8_t* val_buf = new uint8_t[len + 1];
    memcpy(val_buf, data, len);
    val_buf[len] = '\0';
    return new Field(len + 1, val_buf, true);
}

static Field* tmp_field(uint32_t val)
{
    uint32_t* val_buf = new uint32_t[1];
    *val_buf = val;
    return new Field(sizeof(uint32_t), reinterpret_cast<uint8_t*>(val_buf), true);
}

static Field* tmp_field(const std::string& str)
{
    return tmp_field_from_data(reinterpret_cast<const uint8_t*>(str.c_str()), str.length());
}

static Field* tmp_field(const Field& f)
{
    int32_t len = f.length();
    if (len <= 0)
        return new Field(STAT_NOT_PRESENT);

    const uint8_t* data = f.start();
    const uint8_t* end = data + len;
    const uint8_t* p = data;
    for (; p < end; ++p)
    {
        uint8_t c = *p;
        if (c < 0x20 || c > 0x7E || c == '\\')
            break;
    }

    if (p == end)
        return tmp_field_from_data(data, len);  // No escaping needed

    static constexpr char hex_chars[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    std::string escaped;
    escaped.reserve(len * 2);  // Will grow if needed
    escaped.append(reinterpret_cast<const char*>(data), p - data);

    for (; p < end; ++p)
    {
        uint8_t c = *p;

        if (c == '\\')
            escaped.append("\\x5c");
        else if (c < 0x20 || c > 0x7E)
        {
            escaped.append("\\x");
            escaped.push_back(hex_chars[(c >> 4) & 0x0F]);
            escaped.push_back(hex_chars[c & 0x0F]);
        }
        else
            escaped.push_back(c);
    }

    return tmp_field_from_data(reinterpret_cast<const uint8_t*>(escaped.c_str()), escaped.length());
}

Field* HttpMsgSection::compute_http_decoded_uri(const HttpBufferInfo&)
{
    if (request)
    {
        HttpUri* uri = request->get_http_uri();
        if (uri)
            return uri->create_decoded_uri(decoded_path);
    }
    return new Field(STAT_NOT_PRESENT);
}

Field* HttpMsgSection::compute_http_method_str(const HttpBufferInfo&)
{
    return tmp_field(get_classic_buffer(HTTP_BUFFER_METHOD, 0, 0));
}

Field* HttpMsgSection::compute_http_request_size(const HttpBufferInfo&)
{
    uint32_t val = 0;
    val += get_section_len(request);
    val += get_section_len(header[SRC_CLIENT]);
    val += transaction->get_body_len(HttpCommon::SRC_CLIENT);
    val += get_section_len(trailer[SRC_CLIENT]);
    return tmp_field(val);
}

Field* HttpMsgSection::compute_http_response_size(const HttpBufferInfo&)
{
    uint32_t val = 0;
    val += get_section_len(status);
    val += get_section_len(header[SRC_SERVER]);
    val += transaction->get_body_len(HttpCommon::SRC_SERVER);
    val += get_section_len(trailer[SRC_SERVER]);
    return tmp_field(val);
}

Field* HttpMsgSection::compute_http_version_str(const HttpBufferInfo& buf)
{
    VersionId version = get_version_id(buf);
    const auto& iter = VersionEnumToStr.find(version);
    if (iter == VersionEnumToStr.end())
        return new Field(STAT_NOT_PRESENT);

    std::string val = "HTTP/";
    val.append(iter->second);
    return tmp_field(val);
}

Field* HttpMsgSection::compute_http_user_agent_str(const HttpBufferInfo&)
{
    return tmp_field(get_classic_buffer(HTTP_BUFFER_HEADER, HEAD_USER_AGENT, 0));
}

Field* HttpMsgSection::compute_http_referer_str(const HttpBufferInfo&)
{
    return tmp_field(get_classic_buffer(HTTP_BUFFER_HEADER, HEAD_REFERER, 0));
}

Field* HttpMsgSection::compute_detail_119_20(const HttpBufferInfo& buf)
{
    // EVENT_MAX_HEADERS
    // Header Count: XXX
    std::string val = "Header Count: ";
    auto cnt = get_num_headers(buf);
    if (cnt >= 0)
        val.append(std::to_string(cnt));
    else
    {
        val.append("<no header ");
        val.append(std::to_string(cnt));
        val.append(">");
    }

    return tmp_field(val);
}

Field* HttpMsgSection::compute_detail_119_287(const HttpBufferInfo&)
{
    // EVENT_DISALLOWED_METHOD
    // HTTP Method: XXX
    std::string val = "HTTP Method: ";
    const Field& method = get_classic_buffer(HTTP_BUFFER_METHOD, 0, 0);
    if (method.length() > 0)
        val.append(reinterpret_cast<const char*>(method.start()), method.length());
    else
    {
        val.append("<no method ");
        val.append(std::to_string(method.length()));
        val.append(">");
    }

    return tmp_field(val);
}

const Field& HttpMsgSection::get_tmp_buffer(const HttpBufferInfo& buf)
{
    typedef Field* (HttpMsgSection::*ComputeFunction)(const HttpBufferInfo&);

    static const ComputeFunction compute_functions[TMP_BUFFER_CNT] = {
        &HttpMsgSection::compute_http_decoded_uri,      // HTTP_BUFFER_DECODED_URI
        &HttpMsgSection::compute_http_method_str,       // HTTP_BUFFER_METHOD_STR
        &HttpMsgSection::compute_http_request_size,     // HTTP_BUFFER_REQUEST_SIZE
        &HttpMsgSection::compute_http_response_size,    // HTTP_BUFFER_RESPONSE_SIZE
        &HttpMsgSection::compute_http_version_str,      // HTTP_BUFFER_VERSION_STR
        &HttpMsgSection::compute_http_user_agent_str,   // HTTP_BUFFER_USER_AGENT_STR
        &HttpMsgSection::compute_http_referer_str,      // HTTP_BUFFER_REFERER_STR
        &HttpMsgSection::compute_detail_119_20,         // DETAIL_119_20, EVENT_MAX_HEADERS
        &HttpMsgSection::compute_detail_119_287         // DETAIL_119_287, EVENT_DISALLOWED_METHOD
    };

    const unsigned index = buf.type - (HTTP__BUFFER_MAX + 1);
    assert(index < TMP_BUFFER_CNT);

    if (tmp_buffers[index] == nullptr)
        tmp_buffers[index] = (this->*compute_functions[index])(buf);

    assert(tmp_buffers[index] != nullptr);
    return *tmp_buffers[index];
}

HttpMsgSection::HttpMsgSection(const uint8_t* buffer, const uint16_t buf_size,
       HttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
       const HttpParaList* params_) :
    msg_text(buf_size, buffer, buf_owner),
    session_data(session_data_),
    flow(flow_),
    params(params_),
    transaction(HttpTransaction::attach_my_transaction(session_data, source_id_, flow)),
    trans_num(session_data->expected_trans_num[source_id_]),
    status_code_num((source_id_ == SRC_SERVER) ? session_data->status_code_num : STAT_NOT_PRESENT),
    source_id(source_id_),
    version_id(session_data->version_id[source_id]),
    method_id((source_id == SRC_CLIENT) ? session_data->method_id : METH__NOT_PRESENT),
    tcp_close(session_data->tcp_close[source_id])
{
    assert((source_id == SRC_CLIENT) || (source_id == SRC_SERVER));

    if (flow->stream_intf)
    {
        flow->stream_intf->set_hi_msg_section(flow, this);
        return;
    }

    HttpContextData::save_snapshot(this);
}

void HttpMsgSection::add_infraction(int infraction)
{
    *transaction->get_infractions(source_id) += infraction;
}

void HttpMsgSection::create_event(int sid)
{
    session_data->events[source_id]->create_event(sid);
}

void HttpMsgSection::update_depth() const
{
    const int64_t& file_depth_remaining = session_data->file_depth_remaining[source_id];
    const int64_t& detect_depth_remaining = session_data->detect_depth_remaining[source_id];
    const int32_t& publish_depth_remaining = session_data->publish_depth_remaining[source_id];

    unsigned target_size = SnortConfig::get_conf()->max_pdu;

    if ( session_data->compress[source_id] != nullptr and
        session_data->compress[source_id]->get_compression_id() != CMP_NONE )
        target_size = GZIP_BLOCK_SIZE;

    if (detect_depth_remaining <= 0)
    {
        if ((file_depth_remaining <= 0) && (publish_depth_remaining <= 0))
        {
            // Don't need any more of the body
            session_data->section_size_target[source_id] = 0;
        }
        else
        {
            // Need data for file processing or publishing
            session_data->stretch_section_to_packet[source_id] = true;
            const int64_t max_remaining = (file_depth_remaining > publish_depth_remaining) ?
                file_depth_remaining : publish_depth_remaining;
            session_data->section_size_target[source_id] = (max_remaining <= target_size) ?
                max_remaining : target_size;
        }
        return;
    }

    if (detect_depth_remaining <= target_size)
    {
        // Go to detection as soon as detect depth is reached
        session_data->section_size_target[source_id] = detect_depth_remaining;
        session_data->stretch_section_to_packet[source_id] = true;
    }
    else
    {
        // Randomize the split point a little bit to make it harder to evade detection.
        // FlushBucket provides pseudo random numbers in the range 128 to 255.
        const int random_increment = FlushBucket::get_size() - 192;
        assert((random_increment >= -64) && (random_increment <= 63));
        session_data->section_size_target[source_id] = target_size + random_increment;
        session_data->stretch_section_to_packet[source_id] = false;
    }
}

bool HttpMsgSection::run_detection(snort::Packet* p)
{
    if ((p == nullptr) || !detection_required())
        return false;
    DetectionEngine::detect(p);
    return true;
}

const Field& HttpMsgSection::classic_normalize(const Field& raw, Field& norm,
    bool do_path, const HttpParaList::UriParam& uri_param)
{
    if (norm.length() != STAT_NOT_COMPUTE)
        return norm;

    if ((raw.length() <= 0) || !UriNormalizer::classic_need_norm(raw, do_path, uri_param))
    {
        norm.set(raw);
        return norm;
    }
    UriNormalizer::classic_normalize(raw, norm, do_path, uri_param);
    return norm;
}

const Field& HttpMsgSection::get_classic_buffer(unsigned id, uint64_t sub_id, uint64_t form)
{
    const HttpBufferInfo buffer_info(id, sub_id, form);

    return get_classic_buffer(buffer_info);
}

const Field& HttpMsgSection::get_classic_buffer(const HttpBufferInfo& buf)
{
    // buffer_side replaces source_id for rule options that support the request option
    const SourceId buffer_side = (buf.form & FORM_REQUEST) ? SRC_CLIENT : source_id;

    switch (buf.type)
    {
    case HTTP_BUFFER_CLIENT_BODY:
    {
        if (source_id != SRC_CLIENT)
            return Field::FIELD_NULL;
        return (get_body() != nullptr) ? get_body()->get_classic_client_body() : Field::FIELD_NULL;
    }
    case HTTP_BUFFER_COOKIE:
    case HTTP_BUFFER_RAW_COOKIE:
    {
        if (header[buffer_side] == nullptr)
            return Field::FIELD_NULL;
        return (buf.type == HTTP_BUFFER_COOKIE) ? header[buffer_side]->get_classic_norm_cookie() :
            header[buffer_side]->get_classic_raw_cookie();
    }
    case HTTP_BUFFER_HEADER:
    case HTTP_BUFFER_TRAILER:
    case HTTP_HEADER_TEST:
    case HTTP_TRAILER_TEST:
    {
        HttpMsgHeadShared* const head = (buf.type == HTTP_BUFFER_HEADER || buf.type == HTTP_HEADER_TEST) ?
            (HttpMsgHeadShared*)header[buffer_side] : (HttpMsgHeadShared*)trailer[buffer_side];
        if (head == nullptr)
            return Field::FIELD_NULL;
        if (buf.sub_id == 0)
            return head->get_classic_norm_header();
        return head->get_header_value_norm((HeaderId)buf.sub_id);
    }
    case HTTP_BUFFER_METHOD:
    {
        return (request != nullptr) ? request->get_method() : Field::FIELD_NULL;
    }
    case HTTP_BUFFER_RAW_BODY:
    {
        return (get_body() != nullptr) ? get_body()->get_raw_body() : Field::FIELD_NULL;
    }
    case HTTP_BUFFER_RAW_HEADER:
    case HTTP_BUFFER_RAW_TRAILER:
    {
        HttpMsgHeadShared* const head = (buf.type == HTTP_BUFFER_RAW_HEADER) ?
            (HttpMsgHeadShared*)header[buffer_side] : (HttpMsgHeadShared*)trailer[buffer_side];
        if (head == nullptr)
            return Field::FIELD_NULL;
        if (buf.sub_id == 0)
            return head->msg_text;
        return head->get_all_header_values_raw((HeaderId)buf.sub_id);
    }
    case HTTP_BUFFER_RAW_REQUEST:
    {
        return (request != nullptr) ? request->msg_text : Field::FIELD_NULL;
    }
    case HTTP_BUFFER_RAW_STATUS:
    {
        return (status != nullptr) ? status->msg_text : Field::FIELD_NULL;
    }
    case HTTP_BUFFER_STAT_CODE:
    {
        return (status != nullptr) ? status->get_status_code() : Field::FIELD_NULL;
    }
    case HTTP_BUFFER_STAT_MSG:
    {
        return (status != nullptr) ? status->get_reason_phrase() : Field::FIELD_NULL;
    }
    case HTTP_BUFFER_TRUE_IP:
    {
        return (header[SRC_CLIENT] != nullptr) ? header[SRC_CLIENT]->get_true_ip() :
            Field::FIELD_NULL;
    }
    case HTTP_BUFFER_URI:
    case HTTP_BUFFER_RAW_URI:
    case HTTP_BUFFER_DECODED_URI:
    {   
        if (buf.type == HTTP_BUFFER_DECODED_URI && (buf.sub_id == 0 || buf.sub_id == UC_PATH))
        {
            const Field& decoded_uri = get_tmp_buffer(buf);

            if (buf.sub_id == 0)
                return decoded_uri;

            return decoded_path ? *decoded_path : Field::FIELD_NULL;
        }
        const bool raw = (buf.type == HTTP_BUFFER_RAW_URI);
        if (request == nullptr)
            return Field::FIELD_NULL;
        if (buf.sub_id == 0)
            return raw ? request->get_uri() : request->get_uri_norm_classic();
        HttpUri* const uri = request->get_http_uri();
        if (uri == nullptr)
            return Field::FIELD_NULL;
        switch ((UriComponent)buf.sub_id)
        {
        case UC_SCHEME:
            return raw ? uri->get_scheme() : uri->get_norm_scheme();
        case UC_HOST:
            return raw ? uri->get_host() : uri->get_norm_host();
        case UC_PORT:
            return uri->get_port();
        case UC_PATH:
            return raw ? uri->get_path() : uri->get_norm_path();
        case UC_QUERY:
            return raw ? uri->get_query() : uri->get_norm_query();
        case UC_FRAGMENT:
            return raw ? uri->get_fragment() : uri->get_norm_fragment();
        }
        assert(false);
        return Field::FIELD_NULL;
    }
    case HTTP_BUFFER_VERSION:
    {
        HttpMsgStart* start = (buffer_side == SRC_CLIENT) ?
            (HttpMsgStart*)request : (HttpMsgStart*)status;
        return (start != nullptr) ? start->get_version() : Field::FIELD_NULL;
    }
    case BUFFER_VBA_DATA:
    {
        HttpMsgBody* msg_body = get_body();
        if (msg_body)
            return msg_body->get_decomp_vba_data();
        else
            return Field::FIELD_NULL;
    }
    case BUFFER_JS_DATA:
    {
        HttpMsgBody* msg_body = get_body();
        if (msg_body)
            return msg_body->get_norm_js_data();
        else
            return Field::FIELD_NULL;
    }
    default:
        if (buf.type <= HTTP__BUFFER_MAX)
            return Field::FIELD_NULL;
        else if (buf.type <= HTTP__TMP_BUFFER_MAX)
            return get_tmp_buffer(buf);
        assert(false);
        return Field::FIELD_NULL;
    }
}

const Field& HttpMsgSection::get_param_buffer(Cursor& c, const HttpParam& param)
{
    if (request == nullptr)
        return Field::FIELD_NULL;

    HttpUri* query = request->get_http_uri();
    HttpMsgBody* body = (source_id == SRC_CLIENT) ? get_body() : nullptr;

    if (query == nullptr && body == nullptr)
        return Field::FIELD_NULL;

    const HttpParaList::UriParam& uri_config = params->uri_param;

    ParameterMap& query_params = request->get_query_params();
    ParameterMap& body_params = request->get_body_params();

    // cache lookup
    ParameterData& query_data = query_params[param.str_upper()];
    ParameterData& body_data = body_params[param.str_upper()];

    if (!query_data.parsed && query != nullptr)
    {
        // query has not been parsed for this parameter
        const Field& rq = query->get_query();
        const Field& nq = query->get_norm_query();

        if (rq.length() > 0 && nq.length() > 0)
        {
            HttpQueryParser parser(rq.start(), rq.length(),
                nq.start(), nq.length(), uri_config,
                session_data, source_id);

            parser.parse(param, query_data);
            query_data.parsed = true;
        }
    }

    if (!body_data.parsed && body != nullptr)
    {
        // body has not been parsed for this parameter
        const Field& rb = body->get_detect_data();
        const Field& nb = body->get_classic_client_body();

        if (rb.length() > 0 && nb.length() > 0)
        {
            HttpQueryParser parser(rb.start(), rb.length(),
                nb.start(), nb.length(), uri_config,
                session_data, source_id);

            parser.parse(param, body_data);
            body_data.parsed = true;
        }
    }

    KeyValueVec& query_kv = query_data.kv_vec;
    KeyValueVec& body_kv = body_data.kv_vec;

    unsigned num_query_params = query_kv.size();
    unsigned num_body_params = body_kv.size();

    if (num_query_params == 0 && num_body_params == 0)
        return Field::FIELD_NULL;

    // get data stored on the cursor
    HttpCursorData* cd = (HttpCursorData*)c.get_data(HttpCursorData::id);

    if (!cd)
    {
        cd = new HttpCursorData();
        c.set_data(cd);
    }

    // save the parameter count on the cursor
    cd->num_query_params = num_query_params;
    cd->num_body_params = num_body_params;

    unsigned& query_index = cd->query_index;
    unsigned& body_index = cd->body_index;

    while (query_index < num_query_params)
    {
        KeyValue* fields = query_kv[query_index];

        const Field& key = fields->key;
        const Field& value = fields->value;

        ++query_index;

        if (param.is_nocase())
            return value;

        if (!memcmp(key.start(), param.c_str(), key.length()))
            return value;
    }

    while (body_index < num_body_params)
    {
        KeyValue* fields = body_kv[body_index];

        const Field& key = fields->key;
        const Field& value = fields->value;

        ++body_index;

        if (param.is_nocase())
            return value;

        if (!memcmp(key.start(), param.c_str(), key.length()))
            return value;
    }

    return Field::FIELD_NULL;
}

int32_t HttpMsgSection::get_num_headers(const HttpBufferInfo& buf) const
{
    // buffer_side replaces source_id for rule options that support the request option
    const SourceId buffer_side = (buf.form & FORM_REQUEST) ? SRC_CLIENT : source_id;

    const HttpMsgHeadShared* const head = (buf.type == HTTP_RANGE_NUM_TRAILERS) ?
        (HttpMsgHeadShared*)trailer[buffer_side]:
        (HttpMsgHeadShared*)header[buffer_side] ;
    if (head == nullptr)
        return HttpCommon::STAT_NO_SOURCE;

    return head->get_num_headers();
}

int32_t HttpMsgSection::get_max_header_line(const HttpBufferInfo& buf) const
{
    // buffer_side replaces source_id for rule options that support the request option
    const SourceId buffer_side = (buf.form & FORM_REQUEST) ? SRC_CLIENT : source_id;

    const HttpMsgHeadShared* const head = (buf.type == HTTP_RANGE_MAX_TRAILER_LINE) ?
        (HttpMsgHeadShared*)trailer[buffer_side]:
        (HttpMsgHeadShared*)header[buffer_side] ;
    if (head == nullptr)
        return HttpCommon::STAT_NO_SOURCE;

    return head->get_max_header_line();
}

int32_t HttpMsgSection::get_num_cookies(const HttpBufferInfo& buf) const
{
    // buffer_side replaces source_id for rule options that support the request option
    const SourceId buffer_side = (buf.form & FORM_REQUEST) ? SRC_CLIENT : source_id;

    HttpMsgHeader* head = header[buffer_side];
    if (head == nullptr)
        return HttpCommon::STAT_NO_SOURCE;

    return head->get_num_cookies();
}

VersionId HttpMsgSection::get_version_id(const HttpBufferInfo& buf) const
{
    // buffer_side replaces source_id for rule options that support the request option
    const SourceId buffer_side = (buf.form & FORM_REQUEST) ? SRC_CLIENT : source_id;
    HttpMsgStart* start = (buffer_side == SRC_CLIENT) ?
        (HttpMsgStart*)request : (HttpMsgStart*)status;

    return (start != nullptr) ? start->get_version_id() : VERS__NOT_PRESENT;
}

void HttpMsgSection::get_related_sections()
{
    // When a message section is created these relationships become fixed so we make copies for
    // future reference.
    request = transaction->get_request();
    status = transaction->get_status();
    header[SRC_CLIENT] = transaction->get_header(SRC_CLIENT);
    header[SRC_SERVER] = transaction->get_header(SRC_SERVER);
    trailer[SRC_CLIENT] = transaction->get_trailer(SRC_CLIENT);
    trailer[SRC_SERVER] = transaction->get_trailer(SRC_SERVER);
}

void HttpMsgSection::clear()
{
    clear_tmp_buffers();
    transaction->clear_section();
    cleared = true;
}

#ifdef REG_TEST

void HttpMsgSection::print_section_title(FILE* output, const char* title) const
{
    fprintf(output, "HTTP message %" PRIu64 " %s:\n", trans_num, title);
    msg_text.print(output, "Input");
}

void HttpMsgSection::print_section_wrapup(FILE* output) const
{
    fprintf(output, "Infractions: %016" PRIx64 " %016" PRIx64 " %016" PRIx64 ", Events: %016"
        PRIx64 " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 ", TCP Close: %s\n\n",
        transaction->get_infractions(source_id)->get_raw(128),
        transaction->get_infractions(source_id)->get_raw(64),
        transaction->get_infractions(source_id)->get_raw(0),
        session_data->events[source_id]->get_raw(BASE_2XX_EVENTS + 64),
        session_data->events[source_id]->get_raw(BASE_2XX_EVENTS),
        session_data->events[source_id]->get_raw(BASE_1XX_EVENTS),
        session_data->events[source_id]->get_raw(0),
        tcp_close ? "True" : "False");
    if (HttpTestManager::get_show_pegs())
    {
        print_peg_counts(output);
    }
    session_data->show(output);
    fprintf(output, "\n");
}

void HttpMsgSection::print_peg_counts(FILE* output) const
{
    const PegInfo* const peg_names = HttpModule::get_peg_names();
    const PegCount* const peg_counts = HttpModule::get_peg_counts();

    fprintf(output, "Peg Counts\n");
    for (unsigned k = 0; k < PEG_COUNT_MAX; k++)
    {
        if (peg_counts[k] > 0)
        {
            fprintf(output, "%s: %" PRIu64 "\n", peg_names[k].name, peg_counts[k]);
        }
    }
    fprintf(output, "\n");
}

#endif
