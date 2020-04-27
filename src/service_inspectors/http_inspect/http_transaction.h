//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
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
// http_transaction.h author Tom Peters <thopeter@cisco.com>

#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "http_common.h"
#include "http_enum.h"
#include "http_event.h"
#include "http_flow_data.h"

class HttpMsgRequest;
class HttpMsgStatus;
class HttpMsgHeader;
class HttpMsgTrailer;
class HttpMsgSection;
class HttpMsgBody;
class HttpMsgHeadShared;

class HttpTransaction
{
public:
    ~HttpTransaction();
    static HttpTransaction* attach_my_transaction(HttpFlowData* session_data,
        HttpCommon::SourceId source_id);
    static void delete_transaction(HttpTransaction* transaction, HttpFlowData* session_data);

    HttpMsgRequest* get_request() const { return request; }
    void set_request(HttpMsgRequest* request_) { request = request_; }

    HttpMsgStatus* get_status() const { return status; }
    void set_status(HttpMsgStatus* status_) { status = status_; }

    HttpMsgHeader* get_header(HttpCommon::SourceId source_id) const { return header[source_id]; }
    void set_header(HttpMsgHeader* header_, HttpCommon::SourceId source_id)
        { header[source_id] = header_; }

    HttpMsgTrailer* get_trailer(HttpCommon::SourceId source_id) const
        { return trailer[source_id]; }
    void set_trailer(HttpMsgTrailer* trailer_, HttpCommon::SourceId source_id)
        { trailer[source_id] = trailer_; }
    void set_body(HttpMsgBody* latest_body);

    HttpInfractions* get_infractions(HttpCommon::SourceId source_id);

    void set_one_hundred_response();
    bool final_response() const { return !second_response_expected; }

    void clear_section();
    bool is_clear() const { return active_sections == 0; }
    void garbage_collect();

    HttpTransaction* next = nullptr;

    // Each file processed has a unique id per flow: hash(source_id, transaction_id, h2_stream_id)
    // If this is an HTTP/1 flow, h2_stream_id is 0
    void set_file_processing_id(const HttpCommon::SourceId source_id,
        const uint64_t transaction_id, const uint32_t stream_id);
    uint64_t get_file_processing_id(HttpCommon::SourceId source_id)
        { return file_processing_id[source_id]; }

private:
    HttpTransaction(HttpFlowData* session_data_) : session_data(session_data_)
    {
        infractions[0] = nullptr;
        infractions[1] = nullptr;
    }
    void discard_section(HttpMsgSection* section);

    HttpFlowData* const session_data;

    uint64_t active_sections = 0;

    HttpMsgRequest* request = nullptr;
    HttpMsgStatus* status = nullptr;
    HttpMsgHeader* header[2] = { nullptr, nullptr };
    HttpMsgTrailer* trailer[2] = { nullptr, nullptr };
    HttpMsgBody* body_list = nullptr;
    HttpMsgSection* discard_list = nullptr;
    HttpInfractions* infractions[2];

    uint64_t file_processing_id[2] = { 0, 0 };

    bool response_seen = false;
    bool one_hundred_response = false;
    bool second_response_expected = false;

    // This is a form of reference counting that prevents premature/double deletion of a
    // transaction in the fairly rare case where the request and response are received in
    // parallel.
    bool shared_ownership = false;
};

#endif

