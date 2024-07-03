//--------------------------------------------------------------------------
// Copyright (C) 2024-2024 Cisco and/or its affiliates. All rights reserved.
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
// http_transaction_end_event.h author Maya Dagon <mdagon@cisco.com>

#ifndef HTTP_TRANSACTION_END_EVENT_H
#define HTTP_TRANSACTION_END_EVENT_H

#include "framework/data_bus.h"
#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_field.h"

#include "http_event_ids.h"

class HttpFlowData;
class HttpMsgRequest;
class HttpMsgStatus;
class HttpTransaction;

namespace snort
{
// This event is published each time a transaction is ending
class SO_PUBLIC HttpTransactionEndEvent : public snort::DataEvent
{
public:
    HttpTransactionEndEvent(const HttpTransaction* const);

    const Field& get_host_hdr() const;
    const Field& get_uri() const;
    const Field& get_method() const;
    const Field& get_stat_code() const;
    const Field& get_stat_msg() const;
    const Field& get_user_agent() const;
    const Field& get_referer_hdr() const;
    const Field& get_origin_hdr() const;
    HttpEnums::VersionId get_version() const;
    uint64_t get_trans_depth() const;

private:
    const Field& get_client_header(uint64_t sub_id) const;

    const HttpTransaction* const transaction;
};
}
#endif
