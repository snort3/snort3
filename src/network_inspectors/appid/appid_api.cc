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
#include "app_info_table.h"
#include "service_plugins/service_bootp.h"
#include "service_plugins/service_netbios.h"
#include "utils/util.h"
#ifdef ENABLE_APPID_THIRD_PARTY
#include "tp_appid_session_api.h"
#endif

using namespace snort;

#define SSL_WHITELIST_PKT_LIMIT 20

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

const char* AppIdApi::get_application_name(Flow* flow, bool from_client)
{
    const char* app_name = nullptr;
    AppIdSession* asd = get_appid_session(*flow);
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

AppId AppIdApi::get_service_app_id(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->pick_service_app_id();
    else
        return APP_ID_NONE;
}

AppId AppIdApi::get_port_service_app_id(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->service.get_port_service_id();
    else
        return APP_ID_NONE;
}

AppId AppIdApi::get_only_service_app_id(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->pick_only_service_app_id();
    else
        return APP_ID_NONE;
}

AppId AppIdApi::get_misc_app_id(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->pick_misc_app_id();
    else
        return APP_ID_NONE;
}

AppId AppIdApi::get_client_app_id(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->pick_client_app_id();
    else
        return APP_ID_NONE;
}

AppId AppIdApi::get_payload_app_id(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->pick_payload_app_id();
    else
        return APP_ID_NONE;
}

AppId AppIdApi::get_referred_app_id(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->pick_referred_payload_app_id();
    else
        return APP_ID_NONE;
}

AppId AppIdApi::get_fw_service_app_id(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->pick_fw_service_app_id();
    else
        return APP_ID_NONE;
}

AppId AppIdApi::get_fw_misc_app_id(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->pick_fw_misc_app_id();
    else
        return APP_ID_NONE;
}

AppId AppIdApi::get_fw_client_app_id(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->pick_fw_client_app_id();
    else
        return APP_ID_NONE;
}

AppId AppIdApi::get_fw_payload_app_id(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->pick_fw_payload_app_id();
    else
        return APP_ID_NONE;
}

AppId AppIdApi::get_fw_referred_app_id(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->pick_fw_referred_payload_app_id();
    else
        return APP_ID_NONE;
}

bool AppIdApi::is_ssl_session_decrypted(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->is_ssl_session_decrypted();
    return false;
}

bool AppIdApi::is_appid_inspecting_session(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
    {
        if ( asd->common.flow_type == APPID_FLOW_TYPE_NORMAL )
        {
            if ( asd->service_disco_state != APPID_DISCO_STATE_FINISHED ||
                 !asd->is_third_party_appid_done() ||
                 asd->get_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE) ||
                 (asd->get_session_flags(APPID_SESSION_ENCRYPTED) &&
                  (asd->get_session_flags(APPID_SESSION_DECRYPTED) ||
                   asd->session_packet_count < SSL_WHITELIST_PKT_LIMIT)) )
            {
                return true;
            }

            if ( asd->client_disco_state != APPID_DISCO_STATE_FINISHED &&
                (!asd->is_client_detected() ||
                (asd->service_disco_state != APPID_DISCO_STATE_STATEFUL
                && asd->get_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))) )
            {
                return true;
            }

            if ( asd->tp_app_id == APP_ID_SSH && asd->payload.get_id() != APP_ID_SFTP &&
                asd->session_packet_count < MAX_SFTP_PACKET_COUNT )
            {
                return true;
            }
        }
    }

    return false;
}

const char* AppIdApi::get_user_name(Flow& flow, AppId* service, bool* isLoginSuccessful)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
    {
        *service = asd->client.get_user_id();
        *isLoginSuccessful = asd->get_session_flags(APPID_SESSION_LOGIN_SUCCEEDED) ? true : false;
        return asd->client.get_username();
    }

    return nullptr;
}

bool AppIdApi::is_appid_available(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
    {
        if (asd->get_session_flags(APPID_SESSION_NO_TPI))
            return true;
        // FIXIT-M: If a third-party module is not available then this
        //          should probably check if an appId has been discovered
        //          by the local AppId module.
        return asd->is_third_party_appid_available();
    }

    return false;
}

const char* AppIdApi::get_client_version(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->client.get_version();
    else
        return nullptr;
}

uint64_t AppIdApi::get_appid_session_attribute(Flow& flow, uint64_t flags)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->get_session_flags(flags);
    return 0;
}

APPID_FLOW_TYPE AppIdApi::get_flow_type(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->common.flow_type;
    else
        return APPID_FLOW_TYPE_IGNORE;
}

void AppIdApi::get_service_info(Flow& flow, const char** vendor, const char** version,
    AppIdServiceSubtype** subtype)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
    {
        *vendor = asd->service.get_vendor();
        *version = asd->service.get_version();
        *subtype = asd->subtype;
    }
}

short AppIdApi::get_service_port(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->service_port;
    else
        return 0;
}

char* AppIdApi::get_tls_host(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        if (asd->tsession)
            return asd->tsession->tls_host;

    return nullptr;
}

SfIp* AppIdApi::get_service_ip(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return &asd->service_ip;

    return nullptr;
}

SfIp* AppIdApi::get_initiator_ip(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return &asd->common.initiator_ip;

    return nullptr;
}

DHCPData* AppIdApi::get_dhcp_fp_data(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
    if (asd->get_session_flags(APPID_SESSION_HAS_DHCP_FP))
        return static_cast<DHCPData*>(
                        asd->remove_flow_data(APPID_SESSION_DATA_DHCP_FP_DATA));

    return nullptr;
}

void AppIdApi::free_dhcp_fp_data(Flow& flow, DHCPData* data)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
    {
        asd->clear_session_flags(APPID_SESSION_HAS_DHCP_FP);
        BootpServiceDetector::AppIdFreeDhcpData(data);
    }
}

DHCPInfo* AppIdApi::get_dhcp_info(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        if (asd->get_session_flags(APPID_SESSION_HAS_DHCP_INFO))
            return static_cast<DHCPInfo*>(
                        asd->remove_flow_data(APPID_SESSION_DATA_DHCP_INFO));

    return nullptr;
}

void AppIdApi::free_dhcp_info(Flow& flow, DHCPInfo* data)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
    {
        asd->clear_session_flags(APPID_SESSION_HAS_DHCP_INFO);
        BootpServiceDetector::AppIdFreeDhcpInfo(data);
    }
}

FpSMBData* AppIdApi::get_smb_fp_data(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        if (asd->get_session_flags(APPID_SESSION_HAS_SMB_INFO))
            return static_cast<FpSMBData*>(
                        asd->remove_flow_data(APPID_SESSION_DATA_SMB_DATA));

    return nullptr;
}

void AppIdApi::free_smb_fp_data(Flow& flow, FpSMBData* data)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
    {
        asd->clear_session_flags(APPID_SESSION_HAS_SMB_INFO);
        NbdgmServiceDetector::AppIdFreeSMBData(data);
    }
}

const char* AppIdApi::get_netbios_name(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->netbios_name;
    else
        return nullptr;
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
    if ( asd && ( get_flow_type(flow) == APPID_FLOW_TYPE_NORMAL ) )
    {
        appHA->flags = APPID_HA_FLAGS_APP;
        if ( asd->is_third_party_appid_available() )
            appHA->flags |= APPID_HA_FLAGS_TP_DONE;
        if ( asd->is_service_detected() )
            appHA->flags |= APPID_HA_FLAGS_SVC_DONE;
        if ( asd->get_session_flags(APPID_SESSION_HTTP_SESSION) )
            appHA->flags |= APPID_HA_FLAGS_HTTP;
        appHA->appId[0] = asd->tp_app_id;
        appHA->appId[1] = asd->service.get_id();
        appHA->appId[2] = asd->client_inferred_service_id;
        appHA->appId[3] = asd->service.get_port_service_id();
        appHA->appId[4] = asd->payload.get_id();
        appHA->appId[5] = asd->tp_payload_app_id;
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

        asd->tp_app_id = appHA->appId[0];
        asd->service.set_id(appHA->appId[1]);
        asd->client_inferred_service_id = appHA->appId[2];
        asd->service.set_port_service_id(appHA->appId[3]);
        asd->payload.set_id(appHA->appId[4]);
        asd->tp_payload_app_id = appHA->appId[5];
        asd->client.set_id(appHA->appId[6]);
        asd->misc_app_id = appHA->appId[7];
    }
    return sizeof(*appHA);
}

SEARCH_SUPPORT_TYPE AppIdApi::get_http_search(Flow& flow)
{
    SEARCH_SUPPORT_TYPE sst = UNKNOWN_SEARCH_ENGINE;

    if ( AppIdSession* asd = get_appid_session(flow) )
        sst = (asd->search_support_type != UNKNOWN_SEARCH_ENGINE) ?
                        asd->search_support_type : NOT_A_SEARCH_ENGINE;

    return sst;
}

AppIdDnsSession* AppIdApi::get_dns_session(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->get_dns_session();
    else
        return nullptr;
}

AppIdHttpSession* AppIdApi::get_http_session(Flow& flow)
{
    if ( AppIdSession* asd = get_appid_session(flow) )
        return asd->get_http_session();
    else
        return nullptr;
}

bool AppIdApi::is_http_inspection_done(Flow& flow)
{
    bool done = true;

    if ( AppIdSession* asd = get_appid_session(flow) )
        if ( ( asd->common.flow_type == APPID_FLOW_TYPE_NORMAL ) &&
             !asd->is_third_party_appid_done() )
            done = false;

    return done;
}

