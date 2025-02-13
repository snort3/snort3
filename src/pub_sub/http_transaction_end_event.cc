//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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
// http_transaction_end_event.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_transaction_end_event.h"

#include "service_inspectors/http_inspect/http_enum.h"
#include "service_inspectors/http_inspect/http_msg_header.h"
#include "service_inspectors/http_inspect/http_msg_request.h"
#include "service_inspectors/http_inspect/http_msg_section.h"
#include "service_inspectors/http_inspect/http_msg_status.h"
#include "service_inspectors/http_inspect/http_transaction.h"

using namespace snort;
using namespace HttpEnums;

HttpTransactionEndEvent::HttpTransactionEndEvent(const HttpTransaction* const trans)
    : transaction(trans) { }

const Field& HttpTransactionEndEvent::get_client_header(uint64_t sub_id) const
{
    HttpMsgHeader* headers = transaction->get_header(HttpCommon::SRC_CLIENT);
    if (headers == nullptr)
        return Field::FIELD_NULL;

    return headers->get_classic_buffer(HttpEnums::HTTP_BUFFER_HEADER, sub_id, 0);
}

const Field& HttpTransactionEndEvent::get_host_hdr() const
{
    return get_client_header(HttpEnums::HEAD_HOST);
}

const Field& HttpTransactionEndEvent::get_user_agent() const
{
    return get_client_header(HttpEnums::HEAD_USER_AGENT);
}

const Field& HttpTransactionEndEvent::get_referer_hdr() const
{
    return get_client_header(HttpEnums::HEAD_REFERER);
}

const Field& HttpTransactionEndEvent::get_origin_hdr() const
{
    return get_client_header(HttpEnums::HEAD_ORIGIN);
}

const Field& HttpTransactionEndEvent::get_uri() const
{
    if (transaction->get_request() == nullptr)
        return Field::FIELD_NULL;

    return transaction->get_request()->get_classic_buffer(HttpEnums::HTTP_BUFFER_URI, 0, 0);
}

const Field& HttpTransactionEndEvent::get_method() const
{
    if (transaction->get_request() == nullptr)
        return Field::FIELD_NULL;

    return transaction->get_request()->get_method();
}

const Field& HttpTransactionEndEvent::get_stat_code() const
{
    if (transaction->get_status() == nullptr)
        return Field::FIELD_NULL;

    return transaction->get_status()->get_status_code();
}

const Field& HttpTransactionEndEvent::get_stat_msg() const
{
    if (transaction->get_status() == nullptr)
        return Field::FIELD_NULL;

    return transaction->get_status()->get_reason_phrase();
}

HttpEnums::VersionId HttpTransactionEndEvent::get_version() const
{
    auto status = transaction->get_status();
    if (!status and !transaction->get_request())
        return HttpEnums::VERS__NOT_PRESENT;
    return status ? status->get_version_id() : transaction->get_request()->get_version_id();
}

uint64_t HttpTransactionEndEvent::get_trans_depth() const
{
    if (transaction->get_request() != nullptr)
        return transaction->get_request()->get_transaction_id();
    if (transaction->get_status() != nullptr)
        return transaction->get_status()->get_transaction_id();

    return 0;
}

uint64_t HttpTransactionEndEvent::get_request_body_len() const
{
    return transaction->get_body_len(HttpCommon::SRC_CLIENT);
}

uint64_t HttpTransactionEndEvent::get_response_body_len() const
{
    return transaction->get_body_len(HttpCommon::SRC_SERVER);
}

uint8_t HttpTransactionEndEvent::get_info_code() const
{
    return transaction->get_info_code();
}

const Field& HttpTransactionEndEvent::get_info_msg() const
{
    return transaction->get_info_msg();
}

const std::string& HttpTransactionEndEvent::get_filename(HttpCommon::SourceId src_id) const
{
    return transaction->get_filename(src_id);
}

const std::string& HttpTransactionEndEvent::get_content_type(HttpCommon::SourceId src_id) const
{
    return transaction->get_content_type(src_id);
}

const std::string& HttpTransactionEndEvent::get_proxied() const
{
    if (proxies != nullptr)
        return *proxies;

    const std::pair<HeaderId, const char*> proxy_headers[] =
    {
        { HEAD_FORWARDED, "FORWARDED" },
        { HEAD_X_FORWARDED_FOR, "X-FORWARDED-FOR" },
        { HEAD_X_FORWARDED_FROM, "X-FORWARDED-FROM" },
        { HEAD_CLIENT_IP, "CLIENT-IP" },
        { HEAD_VIA, "VIA" },
        { HEAD_XROXY_CONNECTION, "XROXY-CONNECTION" },
        { HEAD_PROXY_CONNECTION, "PROXY-CONNECTION" }
    };

    proxies = new std::string();
    for (auto& hdr: proxy_headers)
    {
        const Field& val = get_client_header(hdr.first);
        if (val.length() > 0)
        {
            if (!proxies->empty())
                proxies->append(" ");
            proxies->append(hdr.second);
            proxies->append("->");
            proxies->append((const char*)val.start(), val.length());
        }
    }

    return *proxies;
}
