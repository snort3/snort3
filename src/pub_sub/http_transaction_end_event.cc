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
