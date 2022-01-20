//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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

// appid_dcerpc_event_handler.h author Eduard Burmai <eburmai@cisco.com>

#ifndef APPID_DCERPC_EVENT_HANDLER_H
#define APPID_DCERPC_EVENT_HANDLER_H

#include "pub_sub/dcerpc_events.h"

#include "appid_session.h"
#include "service_plugins/service_detector.h"

class DceExpSsnEventHandler : public snort::DataHandler
{
public:
    DceExpSsnEventHandler() : DataHandler(MOD_NAME) { }

    void handle(snort::DataEvent& event, snort::Flow* flow) override
    {
        assert(flow);

        AppIdSession* asd = snort::appid_api.get_appid_session(*flow);
        if (!asd or
            !asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
                return;
        else
        {
            // Skip sessions using old odp context after reload detectors
            if (!pkt_thread_odp_ctxt or
                (pkt_thread_odp_ctxt->get_version() != asd->get_odp_ctxt_version()))
                return;
        }

        DceExpectedSessionEvent& map_resp_event = static_cast<DceExpectedSessionEvent&>(event);

        const snort::Packet* pkt = map_resp_event.get_packet();
        const snort::SfIp* src_ip = map_resp_event.get_src_ip();
        const snort::SfIp* dst_ip = map_resp_event.get_dst_ip();
        uint16_t src_port = map_resp_event.get_src_port();
        uint16_t dst_port = map_resp_event.get_dst_port();
        IpProtocol proto = map_resp_event.get_ip_proto();
        SnortProtocolId protocol_id = map_resp_event.get_proto_id();

        AppIdSession* fp = AppIdSession::create_future_session(pkt, src_ip, src_port,
            dst_ip, dst_port, proto, protocol_id);

        if (fp) // initialize data session
        {
            fp->set_service_id(APP_ID_DCE_RPC, asd->get_odp_ctxt());
            asd->initialize_future_session(*fp, APPID_SESSION_IGNORE_ID_FLAGS);
        }
    }
};

#endif // APPID_DCERPC_EVENT_HANDLER_H
