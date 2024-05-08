//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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

// appid_ha.cc author Kani Murthi <kamurthi@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_ha.h"

#include "flow/flow_key.h"
#include "managers/inspector_manager.h"

#include "appid_debug.h"
#include "appid_session.h"
#include "tp_lib_handler.h"

#define APPID_HA_FLAGS_TP_DONE ( 1 << 0 )
#define APPID_HA_FLAGS_SVC_DONE ( 1 << 1 )
#define APPID_HA_FLAGS_HTTP ( 1 << 2 )
#define APPID_HA_FLAGS_DISC_APP ( 1 << 3 )
#define APPID_HA_FLAGS_SPL_MONI ( 1 << 4 )

using namespace snort;

THREAD_LOCAL AppIdHAAppsClient* AppIdHAManager::ha_apps_client = nullptr;
THREAD_LOCAL AppIdHAHttpClient* AppIdHAManager::ha_http_client = nullptr;
THREAD_LOCAL AppIdHATlsHostClient* AppIdHAManager::ha_tls_host_client = nullptr;

static AppIdSession* create_appid_session(Flow& flow, const FlowKey* key,
    AppIdInspector& inspector)
{
    AppIdSession* asd = new AppIdSession(static_cast<IpProtocol>(key->ip_protocol),
        flow.flags.client_initiated ? &flow.client_ip : &flow.server_ip,
        flow.flags.client_initiated ? flow.client_port : flow.server_port, inspector,
        *pkt_thread_odp_ctxt, key->addressSpaceId, key->tenant_id);
        appid_log(CURRENT_PACKET, TRACE_DEBUG_LEVEL, "high-avail - New AppId session created in consume\n");

    flow.set_flow_data(asd);
    asd->flow = &flow;

    return asd;
}

bool AppIdHAAppsClient::consume(Flow*& flow, const FlowKey* key, HAMessage& msg,
    uint8_t size)
{
    assert(key and flow);
    if (size != sizeof(AppIdSessionHAApps))
        return false;

    AppIdInspector* inspector =
        static_cast<AppIdInspector*>(InspectorManager::get_inspector(MOD_NAME, MOD_USAGE, appid_inspector_api.type));

    if (!inspector or !pkt_thread_odp_ctxt)
        return false;

    AppIdSession* asd = (AppIdSession*)(flow->get_flow_data(AppIdSession::inspector_id));
    const AppIdSessionHAApps* appHA = (const AppIdSessionHAApps*)msg.cursor;

    if (appidDebug->is_enabled())
        appidDebug->activate(flow, asd, inspector->get_ctxt().config.log_all_sessions);

    Packet* p = CURRENT_PACKET;
    appid_log(p, TRACE_DEBUG_LEVEL, "high-avail - Consuming app data - flags 0x%x, service %d, "
        "client %d, payload %d, misc %d, referred %d, client_inferred_service %d, "
        "port_service %d, tp_app %d, tp_payload %d\n",
        appHA->flags, appHA->appId[APPID_HA_APP_SERVICE],
        appHA->appId[APPID_HA_APP_CLIENT], appHA->appId[APPID_HA_APP_PAYLOAD],
        appHA->appId[APPID_HA_APP_MISC], appHA->appId[APPID_HA_APP_REFERRED],
        appHA->appId[APPID_HA_APP_CLIENT_INFERRED_SERVICE],
        appHA->appId[APPID_HA_APP_PORT_SERVICE], appHA->appId[APPID_HA_APP_TP],
        appHA->appId[APPID_HA_APP_TP_PAYLOAD]);

    if (!asd)
    {
        asd = create_appid_session(*flow, key, *inspector);
        asd->set_service_id(appHA->appId[APPID_HA_APP_SERVICE], asd->get_odp_ctxt());
        if (asd->get_service_id() == APP_ID_FTP_CONTROL)
        {
            asd->set_session_flags(APPID_SESSION_CLIENT_DETECTED |
                APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_SERVICE_DETECTED);
            if (!ServiceDiscovery::add_ftp_service_state(*asd))
                asd->set_session_flags(APPID_SESSION_CONTINUE);

            asd->service_disco_state = APPID_DISCO_STATE_STATEFUL;
        }
        else
            asd->service_disco_state = APPID_DISCO_STATE_FINISHED;

        asd->client_disco_state = APPID_DISCO_STATE_FINISHED;
        if (asd->get_tp_appid_ctxt() and !ThirdPartyAppIdContext::get_tp_reload_in_progress())
        {
            const TPLibHandler* tph = TPLibHandler::get();
            TpAppIdCreateSession tpsf = tph->tpsession_factory();
            if ( !(asd->tpsession = tpsf(*asd->get_tp_appid_ctxt())) )
                appid_log(p, TRACE_ERROR_LEVEL, "appid: Could not allocate asd.tpsession data in consume");
            else
            {
                asd->tpsession->set_state(TP_STATE_HA);
            }
        }
    }

    if ((appHA->flags & APPID_HA_FLAGS_TP_DONE) and asd->tpsession)
    {
        asd->tpsession->set_state(TP_STATE_TERMINATED);
        asd->set_session_flags(APPID_SESSION_NO_TPI);
    }

    if (appHA->flags & APPID_HA_FLAGS_SVC_DONE)
        asd->set_service_detected();

    if (appHA->flags & APPID_HA_FLAGS_HTTP)
        asd->set_session_flags(APPID_SESSION_HTTP_SESSION);
    if (appHA->flags & APPID_HA_FLAGS_DISC_APP)
        asd->set_session_flags(APPID_SESSION_DISCOVER_APP);
    if (appHA->flags & APPID_HA_FLAGS_SPL_MONI)
        asd->set_session_flags(APPID_SESSION_SPECIAL_MONITORED);
    asd->set_service_id(appHA->appId[APPID_HA_APP_SERVICE], asd->get_odp_ctxt());
    AppIdHttpSession* hsession = nullptr;
    if (appHA->appId[APPID_HA_APP_SERVICE] == APP_ID_HTTP or
        appHA->appId[APPID_HA_APP_SERVICE] == APP_ID_RTMP)
        hsession = asd->create_http_session();
    if (hsession)
    {
        hsession->client.set_id(appHA->appId[APPID_HA_APP_CLIENT]);
        hsession->payload.set_id(appHA->appId[APPID_HA_APP_PAYLOAD]);
        hsession->misc_app_id = appHA->appId[APPID_HA_APP_MISC];
        hsession->referred_payload_app_id = appHA->appId[APPID_HA_APP_REFERRED];
    }
    else
    {
        asd->set_client_id(appHA->appId[APPID_HA_APP_CLIENT]);
        asd->set_payload_id(appHA->appId[APPID_HA_APP_PAYLOAD]);
        asd->misc_app_id = appHA->appId[APPID_HA_APP_MISC];
    }
    asd->client_inferred_service_id = appHA->appId[APPID_HA_APP_CLIENT_INFERRED_SERVICE];
    asd->set_port_service_id(appHA->appId[APPID_HA_APP_PORT_SERVICE]);
    asd->set_tp_app_id(appHA->appId[APPID_HA_APP_TP]);
    asd->set_tp_payload_app_id(appHA->appId[APPID_HA_APP_TP_PAYLOAD]);

    asd->set_consumed_ha_data(true);

    msg.advance_cursor(sizeof(AppIdSessionHAApps));
    return true;
}

bool AppIdHAAppsClient::produce(Flow& flow, HAMessage& msg)
{
    if (!msg.fits(sizeof(AppIdSessionHAApps)))
        return false;
    assert(msg.cursor);

    AppIdSession* asd = (AppIdSession*)flow.get_flow_data(AppIdSession::inspector_id);
    if (!asd)
        return false;

    AppIdSessionHAApps* appHA = (AppIdSessionHAApps*)(msg.cursor);
    if (asd->is_tp_appid_available())
        appHA->flags |= APPID_HA_FLAGS_TP_DONE;
    if (asd->is_service_detected())
        appHA->flags |= APPID_HA_FLAGS_SVC_DONE;
    if (asd->get_session_flags(APPID_SESSION_HTTP_SESSION))
        appHA->flags |= APPID_HA_FLAGS_HTTP;
    if (asd->get_session_flags(APPID_SESSION_DISCOVER_APP))
        appHA->flags |= APPID_HA_FLAGS_DISC_APP;
    if (asd->get_session_flags(APPID_SESSION_SPECIAL_MONITORED))
        appHA->flags |= APPID_HA_FLAGS_SPL_MONI;
    appHA->appId[APPID_HA_APP_SERVICE] = asd->get_service_id();
    const AppIdHttpSession* hsession = asd->get_http_session(0);
    if (hsession)
    {
        appHA->appId[APPID_HA_APP_CLIENT] = hsession->client.get_id();
        appHA->appId[APPID_HA_APP_PAYLOAD] = hsession->payload.get_id();
        appHA->appId[APPID_HA_APP_MISC] = hsession->misc_app_id;
        appHA->appId[APPID_HA_APP_REFERRED] = hsession->referred_payload_app_id;
    }
    else
    {
        appHA->appId[APPID_HA_APP_CLIENT] = asd->get_client_id();
        appHA->appId[APPID_HA_APP_PAYLOAD] = asd->get_payload_id();
        appHA->appId[APPID_HA_APP_MISC] = asd->misc_app_id;
        appHA->appId[APPID_HA_APP_REFERRED] = APP_ID_NONE;
    }
    appHA->appId[APPID_HA_APP_CLIENT_INFERRED_SERVICE] = asd->client_inferred_service_id;
    appHA->appId[APPID_HA_APP_PORT_SERVICE] = asd->get_port_service_id();
    appHA->appId[APPID_HA_APP_TP] = asd->get_tp_app_id();
    appHA->appId[APPID_HA_APP_TP_PAYLOAD] = asd->get_tp_payload_app_id();

    appid_log(CURRENT_PACKET, TRACE_DEBUG_LEVEL, "high-avail - Producing app data - flags 0x%x, service %d, client %d, "
        "payload %d, misc %d, referred %d, client_inferred_service %d, port_service %d, "
        "tp_app %d, tp_payload %d\n",
        appHA->flags, appHA->appId[APPID_HA_APP_SERVICE],
        appHA->appId[APPID_HA_APP_CLIENT], appHA->appId[APPID_HA_APP_PAYLOAD],
        appHA->appId[APPID_HA_APP_MISC], appHA->appId[APPID_HA_APP_REFERRED],
        appHA->appId[APPID_HA_APP_CLIENT_INFERRED_SERVICE],
        appHA->appId[APPID_HA_APP_PORT_SERVICE], appHA->appId[APPID_HA_APP_TP],
        appHA->appId[APPID_HA_APP_TP_PAYLOAD]);

    msg.advance_cursor(sizeof(AppIdSessionHAApps));
    return true;
}

bool AppIdHAHttpClient::consume(Flow*& flow, const FlowKey* key, HAMessage& msg,
    uint8_t size)
{
    assert(key and flow);

    if (size != sizeof(AppIdSessionHAHttp))
        return false;

    AppIdInspector* inspector =
        static_cast<AppIdInspector*>(InspectorManager::get_inspector(MOD_NAME, MOD_USAGE, appid_inspector_api.type));

    if (!inspector or !pkt_thread_odp_ctxt)
        return false;

    AppIdSession* asd = appid_api.get_appid_session(*flow);
    AppIdSessionHAHttp* appHA = (AppIdSessionHAHttp*)msg.cursor;
    if (appidDebug->is_enabled())
        appidDebug->activate(flow, asd, inspector->get_ctxt().config.log_all_sessions);

    appid_log(CURRENT_PACKET, TRACE_DEBUG_LEVEL, "high-avail - Consuming HTTP data - URL %s, host %s\n",
        appHA->url, appHA->host);

    if (!asd)
        asd = create_appid_session(*flow, key, *inspector);

    AppidChangeBits change_bits;
    AppIdHttpSession* hsession = asd->get_http_session();
    if (!hsession)
        hsession = asd->create_http_session();

    hsession->set_field(MISC_URL_FID, new std::string(appHA->url), change_bits);
    hsession->set_field(REQ_HOST_FID, new std::string(appHA->host), change_bits);

    asd->set_consumed_ha_data(true);

    msg.advance_cursor(sizeof(AppIdSessionHAHttp));
    return true;
}

bool AppIdHAHttpClient::produce(Flow& flow, HAMessage& msg)
{
    if (!msg.fits(sizeof(AppIdSessionHAHttp)))
        return false;
    assert(msg.cursor);

    AppIdSession* asd = appid_api.get_appid_session(flow);
    if (!asd)
      return false;

    const AppIdHttpSession* hsession = asd->get_http_session();
    if (!hsession)
        return false;

    const char* url = hsession->get_cfield(MISC_URL_FID);
    const char* host = hsession->get_cfield(REQ_HOST_FID);
    if (!url and !host)
        return false;

    AppIdSessionHAHttp* appHA = (AppIdSessionHAHttp*)msg.cursor;

    if (url)
    {
        auto length = strlen(url);
        if (length >= APPID_HA_MAX_FIELD_LEN)
            length = APPID_HA_MAX_FIELD_LEN - 1;
        memcpy(appHA->url, (void *)url, length);
        appHA->url[length] = '\0';
    }
    else
        appHA->url[0] = '\0';

    if (host)
    {
        auto length = strlen(host);
        if (length >= APPID_HA_MAX_FIELD_LEN)
            length = APPID_HA_MAX_FIELD_LEN - 1;
        memcpy(appHA->host, (void *)host, length);
        appHA->host[length] = '\0';
    }
    else
        appHA->host[0] = '\0';

    appid_log(CURRENT_PACKET, TRACE_DEBUG_LEVEL, "high-avail - Producing HTTP data - URL %s, host %s\n",
        appHA->url, appHA->host);

    msg.advance_cursor(sizeof(AppIdSessionHAHttp));
    return true;
}

bool AppIdHATlsHostClient::consume(Flow*& flow, const FlowKey* key, HAMessage& msg,
    uint8_t size)
{
    assert(key and flow);
    if (size != sizeof(AppIdSessionHATlsHost))
        return false;

    AppIdInspector* inspector =
        static_cast<AppIdInspector*>(InspectorManager::get_inspector(MOD_NAME, MOD_USAGE, appid_inspector_api.type));

    if (!inspector or !pkt_thread_odp_ctxt)
        return false;

    AppIdSession* asd = appid_api.get_appid_session(*flow);
    AppIdSessionHATlsHost* appHA = (AppIdSessionHATlsHost*)msg.cursor;
    if (appidDebug->is_enabled())
        appidDebug->activate(flow, asd, inspector->get_ctxt().config.log_all_sessions);

    appid_log(CURRENT_PACKET, TRACE_DEBUG_LEVEL, "high-avail - Consuming TLS host - %s\n", appHA->tls_host);

    if (!asd)
        asd = create_appid_session(*flow, key, *inspector);

    asd->set_tls_host(appHA->tls_host);

    asd->set_consumed_ha_data(true);

    msg.advance_cursor(sizeof(AppIdSessionHATlsHost));
    return true;
}

bool AppIdHATlsHostClient::produce(Flow& flow, HAMessage& msg)
{
    if (!msg.fits(sizeof(AppIdSessionHATlsHost)))
        return false;
    assert(msg.cursor);

    AppIdSession* asd = appid_api.get_appid_session(flow);
    if (!asd or !asd->get_api().get_tls_host())
        return false;

    AppIdSessionHATlsHost* appHA = (AppIdSessionHATlsHost*)msg.cursor;
    const char* tls_host = asd->get_api().get_tls_host();
    auto length = strlen(tls_host);
    if (length >= APPID_HA_MAX_FIELD_LEN)
        length = APPID_HA_MAX_FIELD_LEN - 1;
    memcpy(appHA->tls_host, tls_host, length);
    appHA->tls_host[length] = '\0';

    appid_log(CURRENT_PACKET, TRACE_DEBUG_LEVEL, "high-avail - Producing TLS host - %s\n", appHA->tls_host);

    msg.advance_cursor(sizeof(AppIdSessionHATlsHost));
    return true;
}
