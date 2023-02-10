//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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

// appid_eve_process_event_handler.cc author Cliff Judge <cljudge@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_eve_process_event_handler.h"
#include "detection/detection_engine.h"

#include "appid_debug.h"
#include "appid_inspector.h"
#include "appid_session.h"

using namespace snort;

void AppIdEveProcessEventHandler::handle(DataEvent& event, Flow* flow)
{
    assert(flow);

    if (!pkt_thread_odp_ctxt)
        return;

    Packet* p = DetectionEngine::get_current_packet();
    assert(p);

    AppIdSession* asd = appid_api.get_appid_session(*flow);
    if (!asd)
    {
        AppidSessionDirection dir;

        dir = p->is_from_client() ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;

        asd = AppIdSession::allocate_session(p, p->get_ip_proto_next(), dir,
            inspector, *pkt_thread_odp_ctxt);
        if (appidDebug->is_enabled())
        {
            appidDebug->activate(flow, asd, inspector.get_ctxt().config.log_all_sessions);
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s New AppId session at mercury event\n",
                    appidDebug->get_debug_session());
        }
    }

    if (!asd->get_session_flags(APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED))
        return;

    if (pkt_thread_odp_ctxt->get_version() != asd->get_odp_ctxt_version())
        return;

    const EveProcessEvent &eve_process_event = static_cast<EveProcessEvent&>(event);

    const std::string& name = eve_process_event.get_process_name();
    uint8_t conf = eve_process_event.get_process_confidence();
    const std::string& server_name = eve_process_event.get_server_name();
    const std::string& user_agent = eve_process_event.get_user_agent();
    std::vector<std::string> alpn_vec = eve_process_event.get_alpn();
    const bool is_quic = eve_process_event.is_flow_quic();
    const bool is_client_process_flag = eve_process_event.is_client_process_mapping();

    OdpContext& odp_ctxt = asd->get_odp_ctxt();

    if (is_quic && alpn_vec.size())
    {
        AppId service_id = APP_ID_NONE;
        service_id = odp_ctxt.get_alpn_matchers().match_alpn_pattern(alpn_vec[0]);
        if (service_id)
        {
            asd->set_alpn_service_app_id(service_id);
            asd->update_encrypted_app_id(service_id);
        }
        else
        {
            asd->set_service_id(APP_ID_QUIC, odp_ctxt);
            asd->set_session_flags(APPID_SESSION_SERVICE_DETECTED);
        }
    }

    AppId client_id = APP_ID_NONE;
    if (!user_agent.empty())
    {
        char* version = nullptr;
        AppId service_id = APP_ID_NONE;

        odp_ctxt.get_http_matchers().identify_user_agent(user_agent.c_str(),
            user_agent.size(), service_id, client_id, &version);

        if (client_id != APP_ID_NONE)
            asd->set_client_appid_data(client_id, version);

        snort_free(version);
    }
    else if (!name.empty() and is_client_process_flag)
    {
        client_id = odp_ctxt.get_eve_ca_matchers().match_eve_ca_pattern(name, conf);

        asd->set_eve_client_app_id(client_id);
    }

    if (!server_name.empty())
    {
        AppId client_id = APP_ID_NONE;
        AppId payload_id = APP_ID_NONE;

        if (!asd->tsession)
            asd->tsession = new TlsSession();

        asd->tsession->set_tls_host(server_name.c_str(), server_name.length());
        asd->set_tls_host();

        odp_ctxt.get_ssl_matchers().scan_hostname(reinterpret_cast<const uint8_t*>(server_name.c_str()),
            server_name.length(), client_id, payload_id);
        asd->set_payload_id(payload_id);
    }

    if (appidDebug->is_active())
    {
        std::string debug_str;

        debug_str += "encrypted client app: " + std::to_string(client_id);
        if (!name.empty())
            debug_str += ", process name: " + name + ", confidence: " + std::to_string(conf);

        if (!server_name.empty())
            debug_str += ", server name: " + server_name;

        if (!user_agent.empty())
            debug_str += ", user agent: " + user_agent;

        if (is_quic && alpn_vec.size())
        {
            debug_str += ", alpn: [ ";
            for(unsigned int i = 0; i < alpn_vec.size(); i++)
                debug_str += alpn_vec[i] + " ";
            debug_str += "]";
        }

        LogMessage("AppIdDbg %s %s\n",
            appidDebug->get_debug_session(), debug_str.c_str());
    }
}
