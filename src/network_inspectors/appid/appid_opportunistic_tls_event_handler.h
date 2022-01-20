//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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

// appid_opportunistic_tls_event_handler.h
// author Sreeja Athirkandathil Narayanan <sathirka@cisco.com>

#ifndef APPID_OPPORTUNISTIC_TLS_EVENT_HANDLER_H
#define APPID_OPPORTUNISTIC_TLS_EVENT_HANDLER_H

#include "pub_sub/opportunistic_tls_event.h"
#include "appid_session.h"

class AppIdOpportunisticTlsEventHandler : public snort::DataHandler
{
public:
    AppIdOpportunisticTlsEventHandler() : DataHandler(MOD_NAME) { }

    void handle(snort::DataEvent&, snort::Flow* flow) override
    {
        assert(flow);
        AppIdSession* asd = snort::appid_api.get_appid_session(*flow);
        if (!asd or
            !asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
                return;

        // Skip sessions using old odp context after reload detectors
        if (!pkt_thread_odp_ctxt or
            (pkt_thread_odp_ctxt->get_version() != asd->get_odp_ctxt_version()))
            return;

        asd->set_session_flags(APPID_SESSION_OPPORTUNISTIC_TLS);
    }
};

#endif

