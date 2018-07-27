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
// http_msg_section.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_section.h"

#include "http_msg_body.h"
#include "http_msg_head_shared.h"
#include "http_msg_header.h"
#include "http_msg_request.h"
#include "http_msg_status.h"
#include "http_msg_trailer.h"
#include "http_test_manager.h"
#include "stream/flush_bucket.h"

using namespace HttpEnums;

HttpMsgSection::HttpMsgSection(const uint8_t* buffer, const uint16_t buf_size,
       HttpFlowData* session_data_, SourceId source_id_, bool buf_owner, snort::Flow* flow_,
       const HttpParaList* params_) :
    msg_text(buf_size, buffer, buf_owner),
    session_data(session_data_),
    flow(flow_),
    params(params_),
    transaction(HttpTransaction::attach_my_transaction(session_data, source_id_)),
    trans_num(session_data->expected_trans_num[source_id_]),
    status_code_num((source_id_ == SRC_SERVER) ? session_data->status_code_num : STAT_NOT_PRESENT),
    source_id(source_id_),
    version_id(session_data->version_id[source_id]),
    method_id((source_id == SRC_CLIENT) ? session_data->method_id : METH__NOT_PRESENT),
    tcp_close(session_data->tcp_close[source_id])
{
    assert((source_id == SRC_CLIENT) || (source_id == SRC_SERVER));
}

bool HttpMsgSection::detection_required() const
{
    return ((msg_text.length() > 0) && (get_inspection_section() != IS_NONE)) ||
           (get_inspection_section() == IS_DETECTION);
}

void HttpMsgSection::add_infraction(int infraction)
{
    *transaction->get_infractions(source_id) += infraction;
}

void HttpMsgSection::create_event(int sid)
{
    transaction->get_events(source_id)->create_event(sid);
}

void HttpMsgSection::update_depth() const
{
    if ((session_data->detect_depth_remaining[source_id] <= 0) &&
        (session_data->detection_status[source_id] == DET_ON))
    {
        session_data->detection_status[source_id] = DET_DEACTIVATING;
    }

    if ((session_data->file_depth_remaining[source_id] <= 0) &&
        (session_data->detect_depth_remaining[source_id] <= 0))
    {
        // Don't need any more of the body
        session_data->section_size_target[source_id] = 0;
        session_data->section_size_max[source_id] = 0;
        return;
    }

    const int random_increment = FlushBucket::get_size() - 192;
    assert((random_increment >= -64) && (random_increment <= 63));

    switch (session_data->compression[source_id])
    {
    case CMP_NONE:
      {
        unsigned max_pdu = snort::SnortConfig::get_conf()->max_pdu;
        session_data->section_size_target[source_id] = max_pdu + random_increment;
        session_data->section_size_max[source_id] = max_pdu + (max_pdu >> 1);
        break;
      }
    case CMP_GZIP:
    case CMP_DEFLATE:
        session_data->section_size_target[source_id] = GZIP_BLOCK_SIZE + random_increment;
        session_data->section_size_max[source_id] = FINAL_GZIP_BLOCK_SIZE;
        break;
    default:
        assert(false);
    }
}

const Field& HttpMsgSection::classic_normalize(const Field& raw, Field& norm,
    const HttpParaList::UriParam& uri_param)
{
    if (norm.length() != STAT_NOT_COMPUTE)
        return norm;

    if ((raw.length() <= 0) || !UriNormalizer::classic_need_norm(raw, true, uri_param))
    {
        norm.set(raw);
        return norm;
    }
    UriNormalizer::classic_normalize(raw, norm, uri_param);
    return norm;
}

const Field& HttpMsgSection::get_classic_buffer(unsigned id, uint64_t sub_id, uint64_t form)
{
    // buffer_side replaces source_id for buffers that support the request option
    const SourceId buffer_side = (form & FORM_REQUEST) ? SRC_CLIENT : source_id;

    switch (id)
    {
    case HTTP_BUFFER_CLIENT_BODY:
      {
        if (source_id != SRC_CLIENT)
            return Field::FIELD_NULL;
        HttpMsgBody* body = transaction->get_body();
        return (body != nullptr) ? body->get_classic_client_body() : Field::FIELD_NULL;
      }
    case HTTP_BUFFER_COOKIE:
    case HTTP_BUFFER_RAW_COOKIE:
      {
        HttpMsgHeader* header = transaction->get_header(buffer_side);
        if (header == nullptr)
            return Field::FIELD_NULL;
        return (id == HTTP_BUFFER_COOKIE) ? header->get_classic_norm_cookie() :
            header->get_classic_raw_cookie();
      }
    case HTTP_BUFFER_HEADER:
    case HTTP_BUFFER_TRAILER:
      {
        // FIXIT-L Someday want to be able to return field name or raw field value
        HttpMsgHeadShared* const header = (id == HTTP_BUFFER_HEADER) ?
            (HttpMsgHeadShared*)transaction->get_header(buffer_side) :
            (HttpMsgHeadShared*)transaction->get_trailer(buffer_side);
        if (header == nullptr)
            return Field::FIELD_NULL;
        if (sub_id == 0)
            return header->get_classic_norm_header();
        return header->get_header_value_norm((HeaderId)sub_id);
      }
    case HTTP_BUFFER_METHOD:
      {
        HttpMsgRequest* request = transaction->get_request();
        return (request != nullptr) ? request->get_method() : Field::FIELD_NULL;
      }
    case HTTP_BUFFER_RAW_BODY:
      {
        HttpMsgBody* body = transaction->get_body();
        return (body != nullptr) ? body->msg_text : Field::FIELD_NULL;
      }
    case HTTP_BUFFER_RAW_HEADER:
      {
        HttpMsgHeader* header = transaction->get_header(buffer_side);
        return (header != nullptr) ? header->get_classic_raw_header() : Field::FIELD_NULL;
      }
    case HTTP_BUFFER_RAW_REQUEST:
      {
        HttpMsgRequest* request = transaction->get_request();
        return (request != nullptr) ? request->msg_text : Field::FIELD_NULL;
      }
    case HTTP_BUFFER_RAW_STATUS:
      {
        HttpMsgStatus* status = transaction->get_status();
        return (status != nullptr) ? status->msg_text : Field::FIELD_NULL;
      }
    case HTTP_BUFFER_RAW_TRAILER:
      {
        HttpMsgTrailer* trailer = transaction->get_trailer(buffer_side);
        return (trailer != nullptr) ? trailer->get_classic_raw_header() : Field::FIELD_NULL;
      }
    case HTTP_BUFFER_STAT_CODE:
      {
        HttpMsgStatus* status = transaction->get_status();
        return (status != nullptr) ? status->get_status_code() : Field::FIELD_NULL;
      }
    case HTTP_BUFFER_STAT_MSG:
      {
        HttpMsgStatus* status = transaction->get_status();
        return (status != nullptr) ? status->get_reason_phrase() : Field::FIELD_NULL;
      }
    case HTTP_BUFFER_TRUE_IP:
      {
        HttpMsgHeader* header = transaction->get_header(SRC_CLIENT);
        return (header != nullptr) ? header->get_true_ip() : Field::FIELD_NULL;
      }
    case HTTP_BUFFER_URI:
    case HTTP_BUFFER_RAW_URI:
      {
        const bool raw = (id == HTTP_BUFFER_RAW_URI);
        HttpMsgRequest* request = transaction->get_request();
        if (request == nullptr)
            return Field::FIELD_NULL;
        if (sub_id == 0)
            return raw ? request->get_uri() : request->get_uri_norm_classic();
        HttpUri* const uri = request->get_http_uri();
        if (uri == nullptr)
            return Field::FIELD_NULL;
        switch ((UriComponent)sub_id)
        {
        case UC_SCHEME:
            return uri->get_scheme();
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
            (HttpMsgStart*)transaction->get_request() : (HttpMsgStart*)transaction->get_status();
        return (start != nullptr) ? start->get_version() : Field::FIELD_NULL;
      }
    default:
        assert(false);
        return Field::FIELD_NULL;
    }
}

#ifdef REG_TEST

void HttpMsgSection::print_section_title(FILE* output, const char* title) const
{
    fprintf(output, "HTTP message %" PRIu64 " %s:\n", trans_num, title);
    msg_text.print(output, "Input");
}

void HttpMsgSection::print_section_wrapup(FILE* output) const
{
    fprintf(output, "Infractions: %016" PRIx64 " %016" PRIx64 ", Events: %016" PRIx64 " %016" PRIx64 " %016"
        PRIx64 ", TCP Close: %s\n\n",
        transaction->get_infractions(source_id)->get_raw2(),
        transaction->get_infractions(source_id)->get_raw(),
        transaction->get_events(source_id)->get_raw3(),
        transaction->get_events(source_id)->get_raw2(),
        transaction->get_events(source_id)->get_raw(),
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

