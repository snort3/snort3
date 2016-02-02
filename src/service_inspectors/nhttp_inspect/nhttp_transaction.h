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
// nhttp_transaction.h author Tom Peters <thopeter@cisco.com>

#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "nhttp_enum.h"
#include "nhttp_flow_data.h"

class NHttpMsgRequest;
class NHttpMsgStatus;
class NHttpMsgHeader;
class NHttpMsgTrailer;
class NHttpMsgSection;
class NHttpMsgBody;
class NHttpMsgHeadShared;

class NHttpTransaction
{
public:
    static NHttpTransaction* attach_my_transaction(NHttpFlowData* session_data,
        NHttpEnums::SourceId source_id);
    ~NHttpTransaction();

    NHttpMsgRequest* get_request() const { return request; }
    void set_request(NHttpMsgRequest* request_) { request = request_; }

    NHttpMsgStatus* get_status() const { return status; }
    void set_status(NHttpMsgStatus* status_) { status = status_; }

    NHttpMsgHeader* get_header(NHttpEnums::SourceId source_id) const { return header[source_id]; }
    void set_header(NHttpMsgHeader* header_, NHttpEnums::SourceId source_id)
        { header[source_id] = header_; }

    NHttpMsgTrailer* get_trailer(NHttpEnums::SourceId source_id) const
        { return trailer[source_id]; }
    void set_trailer(NHttpMsgTrailer* trailer_, NHttpEnums::SourceId source_id)
        { trailer[source_id] = trailer_; }

    NHttpMsgBody* get_body() const { return latest_body; }
    void set_body(NHttpMsgBody* latest_body_) { latest_body = latest_body_; }

private:
    NHttpTransaction() = default;

    NHttpMsgRequest* request = nullptr;
    NHttpMsgStatus* status = nullptr;
    NHttpMsgHeader* header[2] = { nullptr, nullptr };
    NHttpMsgTrailer* trailer[2] = { nullptr, nullptr };
    NHttpMsgBody* latest_body = nullptr;
};

#endif

