//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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

// appid_service_event_handler.cc author Shravan Rangaraju <shrarang@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_service_event_handler.h"

#include "detection/detection_engine.h"
#include "protocols/packet.h"
#include "appid_api.h"
#include "appid_debug.h"
#include "appid_inspector.h"
#include "appid_session.h"

using namespace snort;

void AppIdServiceEventHandler::handle(DataEvent&, Flow* flow)
{
    if (!pkt_thread_odp_ctxt or !flow)
        return;

    Packet* p = DetectionEngine::get_current_packet();
    assert(p);

    // FIXIT-E: For now, wait for snort service inspection only for TCP. In the future, if AppId
    // rolls any of its UDP detectors into service inspectors, below check needs to be removed.
    if (!p->is_tcp())
        return;

    AppIdSession* asd = appid_api.get_appid_session(*flow);
    AppidSessionDirection dir;

    if (asd and asd->initiator_port)
        dir = (asd->initiator_port == p->ptrs.sp) ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    else
        dir = p->is_from_client() ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;

    if (!asd)
    {
        // Event is received before appid has seen any packet. Example, UDP in inline mode
        asd = AppIdSession::allocate_session(p, p->get_ip_proto_next(), dir,
            inspector, *pkt_thread_odp_ctxt);
        if (appidDebug->is_enabled())
            appidDebug->activate(flow, asd, inspector.get_ctxt().config.log_all_sessions);
        APPID_LOG(p, TRACE_DEBUG_LEVEL, "New AppId session at service event\n");
    }
    else if (asd->get_odp_ctxt_version() != pkt_thread_odp_ctxt->get_version())
        return; // Skip detection for sessions using old odp context after odp reload
    if (!asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
        return;

    asd->set_no_service_inspector();

    if (!asd->has_no_service_candidate())
    {
        APPID_LOG(p, TRACE_DEBUG_LEVEL, "No service inspector\n");
        return;
    }

    APPID_LOG(p, TRACE_DEBUG_LEVEL, "No service candidate and no inspector\n");

    const SfIp* service_ip;
    uint16_t port;
    int16_t group;
    auto proto = asd->protocol;

    if (asd->is_service_ip_set())
        std::tie(service_ip, port, group) = asd->get_server_info();
    else
    {
        if (dir == APP_ID_FROM_RESPONDER)
        {
            service_ip = p->ptrs.ip_api.get_src();
            port = p->ptrs.sp;
            group = p->get_ingress_group();
        }
        else
        {
            service_ip = p->ptrs.ip_api.get_dst();
            port = p->ptrs.dp;
            group = p->get_egress_group();
        }
        asd->set_server_info(*service_ip, port, group);
    }

    const SfIp* client_ip;
    if (dir == APP_ID_FROM_RESPONDER)
        client_ip = p->ptrs.ip_api.get_dst();
    else
        client_ip = p->ptrs.ip_api.get_src();

    ServiceDiscoveryState* sds = AppIdServiceState::add(service_ip, proto, port, group, asd->asid,
        asd->is_decrypted(), true);
    asd->get_odp_ctxt().get_service_disco_mgr().fail_service(*asd, p, dir, nullptr, sds);
    sds->set_service_id_failed(*asd, client_ip);
}
