//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// appid_http_end_of_transaction_event_handler.h author Cisco

#ifndef APPID_HTTP_END_OF_TRANSACTION_EVENT_H
#define APPID_HTTP_END_OF_TRANSACTION_EVENT_H

#include "pub_sub/http_transaction_end_event.h"

class AppIdHttpEndOfTransactionEventHandler : public snort::DataHandler
{
public:
    AppIdHttpEndOfTransactionEventHandler() : DataHandler(MOD_NAME) { }

    void handle(snort::DataEvent& event, snort::Flow* flow) override
    {
        if (!pkt_thread_odp_ctxt)
            return;
        assert(flow);
        AppIdSession* asd = snort::appid_api.get_appid_session(*flow);

        if (!asd or
            !asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
            return;
        // Skip sessions using old odp context after reload detectors
        if (pkt_thread_odp_ctxt->get_version() != asd->get_odp_ctxt_version())
            return;

        const snort::HttpTransactionEndEvent* transaction_end_event = static_cast<const snort::HttpTransactionEndEvent*>(&event);
        if (transaction_end_event->get_version() != HttpEnums::VersionId::VERS_2_0)
            return;
        const int64_t stream_id = transaction_end_event->get_httpx_stream_id();
        if (stream_id > 1)
            asd->handle_http2_stream_end_event(stream_id);
    }
};

#endif // APPID_HTTP_END_OF_TRANSACTION_EVENT_H
