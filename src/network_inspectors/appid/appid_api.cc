//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "utils/util.h"

#include "appid_session.h"
#include "appid_session_api.h"
#include "app_info_table.h"
#ifdef ENABLE_APPID_THIRD_PARTY
#include "tp_appid_session_api.h"
#endif

using namespace snort;

namespace snort
{
AppIdApi appid_api;
}

AppIdSession* AppIdApi::get_appid_session(Flow& flow)
{
    AppIdSession* asd = (AppIdSession*)flow.get_flow_data(AppIdSession::inspector_id);

    return (asd && asd->common.flow_type == APPID_FLOW_TYPE_NORMAL) ? asd : nullptr;
}

const char* AppIdApi::get_application_name(AppId app_id)
{
    return AppInfoManager::get_instance().get_app_name(app_id);
}

const char* AppIdApi::get_application_name(Flow& flow, bool from_client)
{
    const char* app_name = nullptr;
    AppIdSession* asd = get_appid_session(flow);
    if ( asd )
    {
        if ( asd->payload.get_id() )
            app_name = AppInfoManager::get_instance().get_app_name(asd->payload.get_id());
        else if ( asd->misc_app_id )
            app_name = AppInfoManager::get_instance().get_app_name(asd->misc_app_id);
        else if ( from_client )
        {
            if ( asd->client.get_id() )
                app_name = AppInfoManager::get_instance().get_app_name(asd->client.get_id());
            else
                app_name = AppInfoManager::get_instance().get_app_name(asd->service.get_id());
        }
        else
        {
            if ( asd->service.get_id() )
                app_name = AppInfoManager::get_instance().get_app_name(asd->service.get_id());
            else
                app_name = AppInfoManager::get_instance().get_app_name(asd->client.get_id());
        }
    }

    return app_name;
}

AppId AppIdApi::get_application_id(const char* appName)
{
    return AppInfoManager::get_instance().get_appid_by_name(appName);
}

#define APPID_HA_FLAGS_APP ( 1 << 0 )
#define APPID_HA_FLAGS_TP_DONE ( 1 << 1 )
#define APPID_HA_FLAGS_SVC_DONE ( 1 << 2 )
#define APPID_HA_FLAGS_HTTP ( 1 << 3 )

uint32_t AppIdApi::produce_ha_state(Flow& flow, uint8_t* buf)
{
    assert(buf);
    AppIdSessionHA* appHA = (AppIdSessionHA*)buf;
    AppIdSession* asd = get_appid_session(flow);
    if ( asd and ( asd->common.flow_type == APPID_FLOW_TYPE_NORMAL ) )
    {
        appHA->flags = APPID_HA_FLAGS_APP;
        if ( asd->is_tp_appid_available() )
            appHA->flags |= APPID_HA_FLAGS_TP_DONE;
        if ( asd->is_service_detected() )
            appHA->flags |= APPID_HA_FLAGS_SVC_DONE;
        if ( asd->get_session_flags(APPID_SESSION_HTTP_SESSION) )
            appHA->flags |= APPID_HA_FLAGS_HTTP;
        appHA->appId[0] = asd->get_tp_app_id();
        appHA->appId[1] = asd->service.get_id();
        appHA->appId[2] = asd->client_inferred_service_id;
        appHA->appId[3] = asd->service.get_port_service_id();
        appHA->appId[4] = asd->payload.get_id();
        appHA->appId[5] = asd->get_tp_payload_app_id();
        appHA->appId[6] = asd->client.get_id();
        appHA->appId[7] = asd->misc_app_id;
    }
    else
        memset(appHA->appId, 0, sizeof(appHA->appId));

    return sizeof(*appHA);
}

// FIXIT-H last param AppIdSession ctor is appid inspector, we need that but no good way to get it
// at the moment...code to allocate session ifdef'ed out until this is resolved...
uint32_t AppIdApi::consume_ha_state(Flow& flow, const uint8_t* buf, uint8_t, IpProtocol /*proto*/,
    SfIp* /*ip*/, uint16_t /*port*/)
{
    const AppIdSessionHA* appHA = (const AppIdSessionHA*)buf;
    if (appHA->flags & APPID_HA_FLAGS_APP)
    {
        AppIdSession* asd =
            (AppIdSession*)(flow.get_flow_data(AppIdSession::inspector_id));

#ifdef APPID_HA_SUPPORT_ENABLED
        if (!asd)
        {
            asd = new AppIdSession(proto, ip, port, nullptr);
            flow.set_flow_data(asd);
            asd->service.set_id(appHA->appId[1]);
            if ( asd->service.get_id() == APP_ID_FTP_CONTROL )
            {
                asd->set_session_flags(APPID_SESSION_CLIENT_DETECTED |
                    APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_SERVICE_DETECTED);
                if ( !ServiceDiscovery::add_ftp_service_state(*asd) )
                    asd->set_session_flags(APPID_SESSION_CONTINUE);

                asd->service_disco_state = APPID_DISCO_STATE_STATEFUL;
            }
            else
                asd->service_disco_state = APPID_DISCO_STATE_FINISHED;

            asd->client_disco_state = APPID_DISCO_STATE_FINISHED;
#ifdef ENABLE_APPID_THIRD_PARTY
            if (asd->tpsession)
                asd->tpsession->set_state(TP_STATE_HA);
#endif
        }
#else
        if ( !asd )
        {
            assert(false);
            return sizeof(*appHA);
        }
#endif

        if( (appHA->flags & APPID_HA_FLAGS_TP_DONE) && asd->tpsession )
        {
#ifdef ENABLE_APPID_THIRD_PARTY
            if( asd->tpsession)
                asd->tpsession->set_state(TP_STATE_TERMINATED);
#endif
            asd->set_session_flags(APPID_SESSION_NO_TPI);
        }

        if (appHA->flags & APPID_HA_FLAGS_SVC_DONE)
            asd->set_service_detected();

        if (appHA->flags & APPID_HA_FLAGS_HTTP)
            asd->set_session_flags(APPID_SESSION_HTTP_SESSION);

        asd->set_tp_app_id(appHA->appId[0]);
        asd->service.set_id(appHA->appId[1]);
        asd->client_inferred_service_id = appHA->appId[2];
        asd->service.set_port_service_id(appHA->appId[3]);
        asd->payload.set_id(appHA->appId[4]);
        asd->set_tp_payload_app_id(appHA->appId[5]);
        asd->client.set_id(appHA->appId[6]);
        asd->misc_app_id = appHA->appId[7];
    }
    return sizeof(*appHA);
}

AppIdSessionApi* AppIdApi::create_appid_session_api(Flow& flow)
{
    AppIdSession* asd = (AppIdSession*)flow.get_flow_data(AppIdSession::inspector_id);

    if (asd and asd->common.flow_type == APPID_FLOW_TYPE_NORMAL)
        return new AppIdSessionApi(asd);

    return nullptr;
}

void AppIdApi::free_appid_session_api(AppIdSessionApi* api)
{
    delete api;
}
