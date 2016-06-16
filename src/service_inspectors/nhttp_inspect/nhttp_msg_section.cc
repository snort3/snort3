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
// nhttp_msg_section.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "nhttp_enum.h"
#include "nhttp_transaction.h"
#include "nhttp_test_manager.h"
#include "nhttp_msg_section.h"
#include "nhttp_msg_request.h"
#include "nhttp_msg_status.h"
#include "nhttp_msg_head_shared.h"
#include "nhttp_msg_header.h"
#include "nhttp_msg_trailer.h"
#include "nhttp_msg_body.h"

using namespace NHttpEnums;

NHttpMsgSection::NHttpMsgSection(const uint8_t* buffer, const uint16_t buf_size,
       NHttpFlowData* session_data_, SourceId source_id_, bool buf_owner, Flow* flow_,
       const NHttpParaList* params_) :
    msg_text(buf_size, buffer),
    session_data(session_data_),
    source_id(source_id_),
    flow(flow_),
    msg_num(session_data->expected_msg_num[source_id]),
    params(params_),
    transaction(NHttpTransaction::attach_my_transaction(session_data, source_id)),
    tcp_close(session_data->tcp_close[source_id]),
    infractions(session_data->infractions[source_id]),
    events(session_data->events[source_id]),
    version_id(session_data->version_id[source_id]),
    method_id((source_id == SRC_CLIENT) ? session_data->method_id : METH__NOT_PRESENT),
    status_code_num((source_id == SRC_SERVER) ? session_data->status_code_num : STAT_NOT_PRESENT),
    delete_msg_on_destruct(buf_owner)
{ }

void NHttpMsgSection::update_depth() const
{
    const int64_t& depth = (session_data->file_depth_remaining[source_id] >=
                            session_data->detect_depth_remaining[source_id]) ?
        session_data->file_depth_remaining[source_id] :
        session_data->detect_depth_remaining[source_id];

    switch (session_data->compression[source_id])
    {
    case CMP_NONE:
      {
        session_data->section_size_target[source_id] = (depth <= DATA_BLOCK_SIZE) ? depth :
            DATA_BLOCK_SIZE;
        session_data->section_size_max[source_id] = (depth <= FINAL_BLOCK_SIZE) ? depth :
            FINAL_BLOCK_SIZE;
        break;
      }
    case CMP_GZIP:
    case CMP_DEFLATE:
        session_data->section_size_target[source_id] = (depth > 0) ? GZIP_BLOCK_SIZE : 0;
        session_data->section_size_max[source_id] = (depth > 0) ? FINAL_GZIP_BLOCK_SIZE : 0;
        break;
    default:
        assert(false);
    }
}

const Field& NHttpMsgSection::classic_normalize(const Field& raw, Field& norm, bool& norm_alloc,
    const NHttpParaList::UriParam& uri_param)
{
    if (norm.length != STAT_NOT_COMPUTE)
        return norm;

    if ((raw.length <= 0) || !UriNormalizer::classic_need_norm(raw, true, uri_param))
    {
        norm.set(raw);
        return norm;
    }
    uint8_t* buffer = new uint8_t[raw.length + UriNormalizer::URI_NORM_EXPANSION];
    UriNormalizer::classic_normalize(raw, norm, buffer, uri_param);
    norm_alloc = true;
    return norm;
}

const Field& NHttpMsgSection::get_classic_buffer(unsigned id, uint64_t sub_id, uint64_t form)
{
    // buffer_side replaces source_id for buffers that support the request option
    const SourceId buffer_side = (form & FORM_REQUEST) ? SRC_CLIENT : source_id;

    switch (id)
    {
    case NHTTP_BUFFER_CLIENT_BODY:
      {
        if (source_id != SRC_CLIENT)
            return Field::FIELD_NULL;
        NHttpMsgBody* body = transaction->get_body();
        return (body != nullptr) ? body->get_classic_client_body() : Field::FIELD_NULL;
      }
    case NHTTP_BUFFER_COOKIE:
    case NHTTP_BUFFER_RAW_COOKIE:
      {
        NHttpMsgHeader* header = transaction->get_header(buffer_side);
        if (header == nullptr)
            return Field::FIELD_NULL;
        return (id == NHTTP_BUFFER_COOKIE) ? header->get_classic_norm_cookie() :
            header->get_classic_raw_cookie();
      }
    case NHTTP_BUFFER_HEADER:
    case NHTTP_BUFFER_TRAILER:
      {
        // FIXIT-L Someday want to be able to return field name or raw field value
        NHttpMsgHeadShared* const header = (id == NHTTP_BUFFER_HEADER) ?
            (NHttpMsgHeadShared*)transaction->get_header(buffer_side) :
            (NHttpMsgHeadShared*)transaction->get_trailer(buffer_side);
        if (header == nullptr)
            return Field::FIELD_NULL;
        if (sub_id == 0)
            return header->get_classic_norm_header();
        return header->get_header_value_norm((HeaderId)sub_id);
      }
    case NHTTP_BUFFER_METHOD:
      {
        NHttpMsgRequest* request = transaction->get_request();
        return (request != nullptr) ? request->get_method() : Field::FIELD_NULL;
      }
    case NHTTP_BUFFER_RAW_HEADER:
      {
        NHttpMsgHeader* header = transaction->get_header(buffer_side);
        return (header != nullptr) ? header->get_classic_raw_header() : Field::FIELD_NULL;
      }
    case NHTTP_BUFFER_STAT_CODE:
      {
        NHttpMsgStatus* status = transaction->get_status();
        return (status != nullptr) ? status->get_status_code() : Field::FIELD_NULL;
      }
    case NHTTP_BUFFER_STAT_MSG:
      {
        NHttpMsgStatus* status = transaction->get_status();
        return (status != nullptr) ? status->get_reason_phrase() : Field::FIELD_NULL;
      }
    case NHTTP_BUFFER_RAW_URI:
    case NHTTP_BUFFER_URI:
      {
        const bool raw = (id == NHTTP_BUFFER_RAW_URI);
        NHttpMsgRequest* request = transaction->get_request();
        if (request == nullptr)
            return Field::FIELD_NULL;
        if (sub_id == 0)
            return raw ? request->get_uri() : request->get_uri_norm_classic();
        NHttpUri* const uri = request->get_nhttp_uri();
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
    case NHTTP_BUFFER_VERSION:
      {
        NHttpMsgStart* start = (buffer_side == SRC_CLIENT) ?
            (NHttpMsgStart*)transaction->get_request() : (NHttpMsgStart*)transaction->get_status();
        return (start != nullptr) ? start->get_version() : Field::FIELD_NULL;
      }
    case NHTTP_BUFFER_RAW_REQUEST:
      {
        NHttpMsgRequest* request = transaction->get_request();
        return (request != nullptr) ? request->get_detect_buf() : Field::FIELD_NULL;
      }
    case NHTTP_BUFFER_RAW_STATUS:
      {
        NHttpMsgStatus* status = transaction->get_status();
        return (status != nullptr) ? status->get_detect_buf() : Field::FIELD_NULL;
      }
    case NHTTP_BUFFER_RAW_TRAILER:
      {
        NHttpMsgTrailer* trailer = transaction->get_trailer(buffer_side);
        return (trailer != nullptr) ? trailer->get_classic_raw_header() : Field::FIELD_NULL;
      }
    default:
        assert(false);
        return Field::FIELD_NULL;
    }
}

#ifdef REG_TEST

void NHttpMsgSection::print_section_title(FILE* output, const char* title) const
{
    fprintf(output, "HTTP message %" PRIu64 " %s:\n", msg_num, title);
    msg_text.print(output, "Input");
}

void NHttpMsgSection::print_section_wrapup(FILE* output) const
{
    fprintf(output, "Infractions: %016" PRIx64 " %016" PRIx64 ", Events: %016" PRIx64 " %016"
        PRIx64 ", TCP Close: %s\n\n", infractions.get_raw2(), infractions.get_raw(),
        events.get_raw2(), events.get_raw(), tcp_close ? "True" : "False");
    if (NHttpTestManager::get_show_pegs())
    {
        print_peg_counts(output);
    }
    session_data->show(output);
    fprintf(output, "\n");
}

void NHttpMsgSection::print_peg_counts(FILE* output) const
{
    const PegInfo* const peg_names = NHttpModule::get_peg_names();
    const PegCount* const peg_counts = NHttpModule::get_peg_counts();

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

