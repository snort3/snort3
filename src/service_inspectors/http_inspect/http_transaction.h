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
// http_transaction.h author Tom Peters <thopeter@cisco.com>

#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "http_enum.h"
#include "http_flow_data.h"

class HttpMsgRequest;
class HttpMsgStatus;
class HttpMsgHeader;
class HttpMsgTrailer;
class HttpMsgSection;
class HttpMsgBody;
class HttpMsgHeadShared;
class HttpInfractions;
class HttpEventGen;

class HttpTransaction
{
public:
    static HttpTransaction* attach_my_transaction(HttpFlowData* session_data,
        HttpEnums::SourceId source_id);
    static void delete_transaction(HttpTransaction* transaction);

    HttpMsgRequest* get_request() const { return request; }
    void set_request(HttpMsgRequest* request_) { request = request_; }

    HttpMsgStatus* get_status() const { return status; }
    void set_status(HttpMsgStatus* status_) { status = status_; }

    HttpMsgHeader* get_header(HttpEnums::SourceId source_id) const { return header[source_id]; }
    void set_header(HttpMsgHeader* header_, HttpEnums::SourceId source_id)
        { header[source_id] = header_; }

    HttpMsgTrailer* get_trailer(HttpEnums::SourceId source_id) const
        { return trailer[source_id]; }
    void set_trailer(HttpMsgTrailer* trailer_, HttpEnums::SourceId source_id)
        { trailer[source_id] = trailer_; }

    HttpMsgBody* get_body() const { return latest_body; }
    void set_body(HttpMsgBody* latest_body_);

    HttpInfractions* get_infractions(HttpEnums::SourceId source_id);
    HttpEventGen* get_events(HttpEnums::SourceId source_id);

    void set_one_hundred_response();
    bool final_response() const { return !second_response_expected; }

private:
    HttpTransaction() = default;
    ~HttpTransaction();

    HttpMsgRequest* request = nullptr;
    HttpMsgStatus* status = nullptr;
    HttpMsgHeader* header[2] = { nullptr, nullptr };
    HttpMsgTrailer* trailer[2] = { nullptr, nullptr };
    HttpMsgBody* latest_body = nullptr;
    HttpInfractions* infractions[2] = { nullptr, nullptr };
    HttpEventGen* events[2] = { nullptr, nullptr };

    bool response_seen = false;
    bool one_hundred_response = false;
    bool second_response_expected = false;

    // This is a form of reference counting that prevents premature/double deletion of a
    // transaction in the fairly rare case where the request and response are received in
    // parallel.
    bool shared_ownership = false;
};

#endif

