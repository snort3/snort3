//--------------------------------------------------------------------------
// Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// appid_api.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_api.h"

#include "framework/inspector.h"
#include "managers/inspector_manager.h"
#include "utils/util.h"

#include "appid_inspector.h"
#include "appid_module.h"
#include "appid_session.h"
#include "appid_session_api.h"
#include "app_info_table.h"
#include "service_plugins/service_ssl.h"
#include "tp_appid_session_api.h"

using namespace snort;

namespace snort
{
AppIdApi appid_api;
}

AppIdSession* AppIdApi::get_appid_session(const Flow& flow)
{
    AppIdSession* asd = (AppIdSession*)flow.get_flow_data(AppIdSession::inspector_id);

    return asd;
}

const char* AppIdApi::get_application_name(AppId app_id, AppIdContext& ctxt)
{
    return ctxt.get_odp_ctxt().get_app_info_mgr().get_app_name(app_id);
}

const char* AppIdApi::get_application_name(const Flow& flow, bool from_client)
{
    const char* app_name = nullptr;
    AppIdSession* asd = get_appid_session(flow);
    if (asd)
    {
        AppId appid = asd->pick_ss_payload_app_id();
        if (appid <= APP_ID_NONE)
            appid = asd->pick_ss_misc_app_id();
        if (!appid and from_client)
        {
            appid = asd->pick_ss_client_app_id();
            if (!appid)
                appid = asd->pick_service_app_id();
        }
        else if (!appid)
        {
            appid = asd->pick_service_app_id();
            if (!appid)
                appid = asd->pick_ss_client_app_id();
        }
        if (appid > APP_ID_NONE && appid < SF_APPID_MAX)
            app_name = asd->ctxt.get_odp_ctxt().get_app_info_mgr().get_app_name(appid);

    }

    return app_name;
}

AppId AppIdApi::get_application_id(const char* appName, AppIdContext& ctxt)
{
    return ctxt.get_odp_ctxt().get_app_info_mgr().get_appid_by_name(appName);
}

#define APPID_HA_FLAGS_APP ( 1 << 0 )
#define APPID_HA_FLAGS_TP_DONE ( 1 << 1 )
#define APPID_HA_FLAGS_SVC_DONE ( 1 << 2 )
#define APPID_HA_FLAGS_HTTP ( 1 << 3 )

uint32_t AppIdApi::produce_ha_state(const Flow& flow, uint8_t* buf)
{
    assert(buf);
    AppIdSessionHA* appHA = (AppIdSessionHA*)buf;
    AppIdSession* asd = get_appid_session(flow);
    if (asd)
    {
        appHA->flags = APPID_HA_FLAGS_APP;
        if (asd->is_tp_appid_available())
            appHA->flags |= APPID_HA_FLAGS_TP_DONE;
        if (asd->is_service_detected())
            appHA->flags |= APPID_HA_FLAGS_SVC_DONE;
        if (asd->get_session_flags(APPID_SESSION_HTTP_SESSION))
            appHA->flags |= APPID_HA_FLAGS_HTTP;
        appHA->appId[0] = asd->get_tp_app_id();
        appHA->appId[1] = asd->service.get_id();
        appHA->appId[2] = asd->client_inferred_service_id;
        appHA->appId[3] = asd->service.get_port_service_id();
        AppIdHttpSession* hsession = asd->get_http_session();
        if (hsession)
            appHA->appId[4] = hsession->payload.get_id();
        else
            appHA->appId[4] = asd->payload.get_id();
        appHA->appId[5] = asd->get_tp_payload_app_id();
        if (hsession)
            appHA->appId[6] = hsession->client.get_id();
        else
            appHA->appId[6] = asd->client.get_id();
        appHA->appId[7] = asd->misc_app_id;
    }
    else
        memset(appHA, 0, sizeof(*appHA));

    return sizeof(*appHA);
}

uint32_t AppIdApi::consume_ha_state(Flow& flow, const uint8_t* buf, uint8_t, IpProtocol proto,
    SfIp* ip, uint16_t port)
{
    const AppIdSessionHA* appHA = (const AppIdSessionHA*)buf;
    if (appHA->flags & APPID_HA_FLAGS_APP)
    {
        AppIdSession* asd =
            (AppIdSession*)(flow.get_flow_data(AppIdSession::inspector_id));

        if (!asd)
        {
            AppIdInspector* inspector = (AppIdInspector*) InspectorManager::get_inspector(MOD_NAME, true);
            if(inspector)
            {

                asd = new AppIdSession(proto, ip, port, *inspector);
                flow.set_flow_data(asd);
                asd->service.set_id(appHA->appId[1], asd->ctxt.get_odp_ctxt());
                if (asd->service.get_id() == APP_ID_FTP_CONTROL)
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
                if (asd->tpsession)
                    asd->tpsession->set_state(TP_STATE_HA);
            }
        }

        if (!asd)
        {
            return sizeof(*appHA);
        }

        if((appHA->flags & APPID_HA_FLAGS_TP_DONE) && asd->tpsession)
        {
            asd->tpsession->set_state(TP_STATE_TERMINATED);
            asd->set_session_flags(APPID_SESSION_NO_TPI);
        }

        if (appHA->flags & APPID_HA_FLAGS_SVC_DONE)
            asd->set_service_detected();

        if (appHA->flags & APPID_HA_FLAGS_HTTP)
            asd->set_session_flags(APPID_SESSION_HTTP_SESSION);

        asd->set_tp_app_id(appHA->appId[0]);
        asd->service.set_id(appHA->appId[1], asd->ctxt.get_odp_ctxt());
        asd->client_inferred_service_id = appHA->appId[2];
        asd->service.set_port_service_id(appHA->appId[3]);
        AppIdHttpSession* hsession = nullptr;
        if (appHA->appId[1] == APP_ID_HTTP or appHA->appId[1] == APP_ID_RTMP)
            hsession = asd->create_http_session();
        if (hsession)
            hsession->payload.set_id(appHA->appId[4]);
        else
            asd->payload.set_id(appHA->appId[4]);
        asd->set_tp_payload_app_id(appHA->appId[5]);
        if (hsession)
            hsession->client.set_id(appHA->appId[6]);
        else
            asd->client.set_id(appHA->appId[6]);
        asd->misc_app_id = appHA->appId[7];
    }
    return sizeof(*appHA);
}

bool AppIdApi::ssl_app_group_id_lookup(Flow* flow, const char* server_name,
    const char* first_alt_name, const char* common_name, const char* org_unit,
    bool sni_mismatch, AppId& service_id, AppId& client_id, AppId& payload_id)
{
    AppIdSession* asd = nullptr;
    service_id = APP_ID_NONE;
    client_id = APP_ID_NONE;
    payload_id = APP_ID_NONE;

    if (flow)
        asd = get_appid_session(*flow);

    if (asd)
    {
        AppidChangeBits change_bits;
        SslPatternMatchers& ssl_matchers = asd->ctxt.get_odp_ctxt().get_ssl_matchers();
        if (!asd->tsession)
            asd->tsession = new TlsSession();
        else if (sni_mismatch)
            asd->tsession->set_tls_host(nullptr, 0, change_bits);

        if (sni_mismatch)
            asd->scan_flags |= SCAN_SPOOFED_SNI_FLAG;

        if (server_name and !sni_mismatch)
        {
            asd->tsession->set_tls_host(server_name, strlen(server_name), change_bits);
            ssl_matchers.scan_hostname((const uint8_t*)server_name, strlen(server_name),
                client_id, payload_id);
            if (client_id != APP_ID_NONE or payload_id != APP_ID_NONE)
                asd->tsession->set_matched_tls_type(MatchedTlsType::MATCHED_TLS_HOST);
        }

        if (first_alt_name)
        {
            asd->tsession->set_tls_first_alt_name(first_alt_name, strlen(first_alt_name), change_bits);
            if (client_id == APP_ID_NONE and payload_id == APP_ID_NONE)
            {
                ssl_matchers.scan_hostname((const uint8_t*)first_alt_name, strlen(first_alt_name),
                    client_id, payload_id);
                if (client_id != APP_ID_NONE or payload_id != APP_ID_NONE)
                    asd->tsession->set_matched_tls_type(MatchedTlsType::MATCHED_TLS_FIRST_SAN);
            }
        }

        if (common_name)
        {
            asd->tsession->set_tls_cname(common_name, strlen(common_name), change_bits);
            if (client_id == APP_ID_NONE and payload_id == APP_ID_NONE)
            {
                ssl_matchers.scan_cname((const uint8_t*)common_name, strlen(common_name),
                    client_id, payload_id);
                if (client_id != APP_ID_NONE or payload_id != APP_ID_NONE)
                    asd->tsession->set_matched_tls_type(MatchedTlsType::MATCHED_TLS_CNAME);
            }
        }

        if (org_unit)
        {
            asd->tsession->set_tls_org_unit(org_unit, strlen(org_unit));
            if (client_id == APP_ID_NONE and payload_id == APP_ID_NONE)
            {
                ssl_matchers.scan_cname((const uint8_t*)org_unit, strlen(org_unit),
                    client_id, payload_id);
                if (client_id != APP_ID_NONE or payload_id != APP_ID_NONE)
                    asd->tsession->set_matched_tls_type(MatchedTlsType::MATCHED_TLS_ORG_UNIT);
            }
        }

        asd->scan_flags |= SCAN_CERTVIZ_ENABLED_FLAG;

        service_id = asd->get_application_ids_service();
        AppId misc_id = asd->get_application_ids_misc();

        if (client_id == APP_ID_NONE)
            client_id = asd->get_application_ids_client();
        else
            asd->client.set_id(client_id);

        if (payload_id == APP_ID_NONE)
            payload_id = asd->get_application_ids_payload();
        else
            asd->payload.set_id(payload_id);

        asd->set_ss_application_ids(service_id, client_id, payload_id, misc_id, change_bits);

        asd->publish_appid_event(change_bits, flow);
    }
    else
    {
        AppIdInspector* inspector = (AppIdInspector*) InspectorManager::get_inspector(MOD_NAME, true);
        if (inspector)
        {
            SslPatternMatchers& ssl_matchers = inspector->get_ctxt().get_odp_ctxt().get_ssl_matchers();

            if (server_name and !sni_mismatch)
                ssl_matchers.scan_hostname((const uint8_t*)server_name, strlen(server_name),
                    client_id, payload_id);
            if (first_alt_name and client_id == APP_ID_NONE and payload_id == APP_ID_NONE)
                ssl_matchers.scan_hostname((const uint8_t*)first_alt_name, strlen(first_alt_name),
                    client_id, payload_id);
            if (common_name and client_id == APP_ID_NONE and payload_id == APP_ID_NONE)
                ssl_matchers.scan_cname((const uint8_t*)common_name, strlen(common_name), client_id,
                    payload_id);
            if (org_unit and client_id == APP_ID_NONE and payload_id == APP_ID_NONE)
                ssl_matchers.scan_cname((const uint8_t*)org_unit, strlen(org_unit), client_id,
                    payload_id);
        }
    }

    if (service_id != APP_ID_NONE or client_id != APP_ID_NONE or payload_id != APP_ID_NONE)
    {
        return true;
    }

    return false;
}

AppIdSessionApi* AppIdApi::create_appid_session_api(const Flow& flow)
{
    AppIdSession* asd = (AppIdSession*)flow.get_flow_data(AppIdSession::inspector_id);

    if (asd)
        return new AppIdSessionApi(asd);

    return nullptr;
}

void AppIdApi::free_appid_session_api(AppIdSessionApi* api)
{
    delete api;
}

bool AppIdApi::is_inspection_needed(const Inspector& inspector) const
{
    AppIdInspector* appid_inspector = (AppIdInspector*) InspectorManager::get_inspector(MOD_NAME,
        true);

    if (appid_inspector and
        (inspector.get_service() == appid_inspector->get_ctxt().config.snortId_for_http2))
        return true;

    return false;
}
