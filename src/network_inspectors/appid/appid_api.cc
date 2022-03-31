//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/detection_engine.h"
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

const char* AppIdApi::get_application_name(AppId app_id, OdpContext& odp_ctxt)
{
    return odp_ctxt.get_app_info_mgr().get_app_name(app_id);
}

const char* AppIdApi::get_application_name(AppId app_id, const Flow& flow)
{
    const char* app_name = nullptr;
    AppIdSession* asd = get_appid_session(flow);
    if (asd)
    {
        // Skip sessions using old odp context after odp reload
        if (!pkt_thread_odp_ctxt or
            pkt_thread_odp_ctxt->get_version() != asd->get_odp_ctxt_version())
            return nullptr;

        if (app_id == APP_ID_UNKNOWN)
            return "unknown";
        app_name = asd->get_odp_ctxt().get_app_info_mgr().get_app_name(app_id);
    }

    return app_name;
}

const char* AppIdApi::get_application_name(const Flow& flow, bool from_client)
{
    const char* app_name = nullptr;
    AppIdSession* asd = get_appid_session(flow);
    if (asd)
    {
        // Skip sessions using old odp context after odp reload
        if (!pkt_thread_odp_ctxt or
            pkt_thread_odp_ctxt->get_version() != asd->get_odp_ctxt_version())
            return nullptr;

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
            app_name = asd->get_odp_ctxt().get_app_info_mgr().get_app_name(appid);

    }

    return app_name;
}

AppId AppIdApi::get_application_id(const char* appName, const AppIdContext& ctxt)
{
    return ctxt.get_odp_ctxt().get_app_info_mgr().get_appid_by_name(appName);
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
        // Skip detection for sessions using old odp context after odp reload
        if (!pkt_thread_odp_ctxt or
            pkt_thread_odp_ctxt->get_version() != asd->get_odp_ctxt_version())
            return false;

        AppidChangeBits change_bits;
        SslPatternMatchers& ssl_matchers = asd->get_odp_ctxt().get_ssl_matchers();
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

        service_id = asd->get_api().get_service_app_id();

        if (asd->use_eve_client_app_id())
            client_id = asd->get_eve_client_app_id();
        else if (client_id == APP_ID_NONE)
            client_id = asd->get_api().get_client_app_id();
        else
            asd->set_client_id(client_id);

        if (payload_id == APP_ID_NONE)
            payload_id = asd->get_api().get_payload_app_id();
        else
            asd->set_payload_id(payload_id);

        asd->set_ss_application_ids(client_id, payload_id, change_bits);
        asd->set_tls_host(change_bits);

        Packet* p = DetectionEngine::get_current_packet();
        assert(p);
        asd->publish_appid_event(change_bits, *p);
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

    if (client_id != APP_ID_NONE or payload_id != APP_ID_NONE)
    {
        return true;
    }

    return false;
}

const AppIdSessionApi* AppIdApi::get_appid_session_api(const Flow& flow) const
{
    AppIdSession* asd = (AppIdSession*)flow.get_flow_data(AppIdSession::inspector_id);

    if (asd)
        return &asd->get_api();

    return nullptr;
}

bool AppIdApi::is_inspection_needed(const Inspector& inspector) const
{
    AppIdInspector* appid_inspector = (AppIdInspector*) InspectorManager::get_inspector(MOD_NAME,
        true);

    if (!appid_inspector)
        return false;

    SnortProtocolId id = inspector.get_service();
    const AppIdConfig& config = appid_inspector->get_ctxt().config;
    if (id == config.snort_proto_ids[PROTO_INDEX_HTTP2] or id == config.snort_proto_ids[PROTO_INDEX_SSH])
        return true;

    return false;
}

const char* AppIdApi::get_appid_detector_directory() const
{
    AppIdInspector* inspector = (AppIdInspector*) InspectorManager::get_inspector(MOD_NAME, true);
    if (!inspector)
        return "";

    return inspector->get_config().app_detector_dir;
}
