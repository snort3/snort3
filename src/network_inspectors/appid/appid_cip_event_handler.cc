//--------------------------------------------------------------------------
// Copyright (C) 2023-2024 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License Version 2 as
// published by the Free Software Foundation.  You may not use, modify or
// distribute this program under any other version of the GNU General
// Public License.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
// --------------------------------------------------------------------------------
// appid_cip_event_handler.cc author Suriya Balu <subalu@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_cip_event_handler.h"
#include "detector_plugins/cip_patterns.h"
#include "appid_debug.h"

using namespace snort;

void CipEventHandler::client_handler(AppIdSession& asd)
{
    asd.set_client_id(APP_ID_CIP);
    asd.set_client_detected();
    asd.client_inferred_service_id = APP_ID_CIP;
}

void CipEventHandler::service_handler(const Packet& p, AppIdSession& asd)
{
    int16_t group;
    uint16_t port;
    const SfIp* ip;

    if (p.is_from_client())
    {
        ip = p.ptrs.ip_api.get_dst();
        port = p.ptrs.dp;
        group = p.get_egress_group();
    }
    else
    {
        ip = p.ptrs.ip_api.get_src();
        port = p.ptrs.sp;
        group = p.get_ingress_group();
    }

    asd.set_server_info(*ip, port, group);
    asd.set_service_id(APP_ID_CIP, asd.get_odp_ctxt());
    asd.set_service_detected();
}

void CipEventHandler::handle(DataEvent& event, Flow* flow)
{
    if (!flow)
        return;

    AppIdSession* asd = appid_api.get_appid_session(*flow);

    if (!asd)
        return;

    if (!pkt_thread_odp_ctxt or (asd->get_odp_ctxt_version() != pkt_thread_odp_ctxt->get_version()))
        return;

    if (!asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
        return;

    CipEvent& cip_event = (CipEvent&)event;
    const CipEventData* event_data = cip_event.get_event_data();

    if (!event_data)
        return;

    const Packet* p = cip_event.get_packet();
    assert(p);

    AppidChangeBits change_bits;
    client_handler(*asd);
    service_handler(*p, *asd);
    AppId payload_id = asd->get_odp_ctxt().get_cip_matchers().get_cip_payload_id(event_data);
    asd->set_payload_id(payload_id);
    asd->set_ss_application_ids(APP_ID_CIP, APP_ID_CIP, payload_id, APP_ID_NONE, APP_ID_NONE, change_bits);

    if (change_bits[APPID_PAYLOAD_BIT])
    {
        if (appidDebug->is_enabled())
            appidDebug->activate(flow, asd, inspector.get_ctxt().config.log_all_sessions);

        const char* app_name_service = asd->get_odp_ctxt().get_app_info_mgr().get_app_name(APP_ID_CIP);
        const char* app_name_payload = asd->get_odp_ctxt().get_app_info_mgr().get_app_name(payload_id);
        appid_log(p, TRACE_DEBUG_LEVEL, "CIP event handler service %s (%d) and payload %s (%d) are detected\n",
            app_name_service, APP_ID_CIP, app_name_payload, payload_id);
    }

    asd->publish_appid_event(change_bits, *p);
}
