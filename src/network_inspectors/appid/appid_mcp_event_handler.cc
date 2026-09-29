//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_mcp_event_handler.h"

#include "detection/detection_engine.h"
#include "pub_sub/mcp_detection_event.h"

#include "appid_api.h"
#include "appid_debug.h"
#include "appid_http_session.h"
#include "appid_inspector.h"
#include "appid_session.h"

using namespace snort;

AppIdMcpEventHandler::AppIdMcpEventHandler(AppIdInspector& inspector)
    : DataHandler(MOD_NAME), inspector(inspector)
{ }

void AppIdMcpEventHandler::handle(DataEvent& event, Flow* flow)
{
    if (!flow or !pkt_thread_odp_ctxt)
        return;

    const Packet* p = DetectionEngine::get_current_packet();
    if (!p)
        return;

    AppIdSession* asd = appid_api.get_appid_session(*flow);
    if (!asd)
    {
        const AppidSessionDirection dir = p->is_from_client() ?
            APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
        asd = AppIdSession::allocate_session(p, p->get_ip_proto_next(), dir,
            inspector, *pkt_thread_odp_ctxt);
        if (!asd)
            return;
    }

    if (!asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED) or
        pkt_thread_odp_ctxt->get_version() != asd->get_odp_ctxt_version())
        return;

    if (appidDebug and appidDebug->is_enabled())
        appidDebug->activate(flow, asd, inspector.get_ctxt().config.log_all_sessions);

    const auto& mcp_event = static_cast<const McpDetectionEvent&>(event);
    AppidChangeBits change_bits;
    uint32_t stream_index = 0;

    AppIdHttpSession* hsession = nullptr;
    const bool is_httpx = mcp_event.is_httpx();

    // MCP detection follows the global HTTP header handler, which initializes the
    // matching AppID HTTP session and owns its lifecycle.
    if (is_httpx)
        hsession = asd->get_matching_http_session(mcp_event.get_stream_id(), stream_index);
    else
        hsession = asd->get_http_session();

    if (!hsession)
        return;

    hsession->set_payload(APP_ID_MCP, change_bits, "MCP event");
    if (!is_httpx)
    {
        asd->set_payload_id(APP_ID_MCP);
        asd->set_ss_application_ids_payload(APP_ID_MCP, change_bits);
    }
    asd->publish_appid_event(change_bits, *p, is_httpx, stream_index);
}
