//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
#include "appid_http_session.h"
#include "app_info_table.h"
#include "thirdparty_appid_utils.h"
#include "service_plugins/service_bootp.h"
#include "service_plugins/service_netbios.h"
#include "utils/util.h"

#define SSL_WHITELIST_PKT_LIMIT 20

AppIdApi appid_api;

AppIdSession* AppIdApi::get_appid_session(Flow* flow)
{
    AppIdSession* asd = (AppIdSession*)flow->get_flow_data(AppIdSession::inspector_id);

    return (asd && asd->common.flow_type == APPID_FLOW_TYPE_NORMAL) ?
           asd : nullptr;
}

const char* AppIdApi::get_application_name(int32_t app_id)
{
    return AppInfoManager::get_instance().get_app_name(app_id);
}

const char* AppIdApi::get_application_name(Flow* flow, bool from_client)
{
    const char* app_name = nullptr;
    AppIdSession* asd = (AppIdSession*)flow->get_flow_data(AppIdSession::inspector_id);

    if ( asd )
    {

        if ( asd->payload_app_id )
            app_name = AppInfoManager::get_instance().get_app_name(asd->payload_app_id);
        else if ( asd->misc_app_id )
            app_name = AppInfoManager::get_instance().get_app_name(asd->misc_app_id);
        else if ( from_client )
        {
            if ( asd->client_app_id )
                app_name = AppInfoManager::get_instance().get_app_name(asd->client_app_id);
            else
                app_name = AppInfoManager::get_instance().get_app_name(asd->service_app_id);
        }
        else
        {
            if ( asd->service_app_id )
                app_name = AppInfoManager::get_instance().get_app_name(asd->service_app_id);
            else
                app_name = AppInfoManager::get_instance().get_app_name(asd->client_app_id);
        }
    }

    return app_name;
}

AppId AppIdApi::get_application_id(const char* appName)
{
    return AppInfoManager::get_instance().get_appid_by_name(appName);
}

AppId AppIdApi::get_service_app_id(AppIdSession* asd)
{
    if (asd)
        return asd->pick_service_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_port_service_app_id(AppIdSession* asd)
{
    if (asd)
        return asd->port_service_id;
    return APP_ID_NONE;
}

AppId AppIdApi::get_only_service_app_id(AppIdSession* asd)
{
    if (asd)
        return asd->pick_only_service_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_misc_app_id(AppIdSession* asd)
{
    if (asd)
        return asd->pick_misc_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_client_app_id(AppIdSession* asd)
{
    if (asd)
        return asd->pick_client_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_payload_app_id(AppIdSession* asd)
{
    if (asd)
        return asd->pick_payload_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_referred_app_id(AppIdSession* asd)
{
    if (asd)
        return asd->pick_referred_payload_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_fw_service_app_id(AppIdSession* asd)
{
    if (asd)
        return asd->pick_fw_service_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_fw_misc_app_id(AppIdSession* asd)
{
    if (asd)
        return asd->pick_fw_misc_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_fw_client_app_id(AppIdSession* asd)
{
    if (asd)
        return asd->pick_fw_client_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_fw_payload_app_id(AppIdSession* asd)
{
    if (asd)
        return asd->pick_fw_payload_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_fw_referred_app_id(AppIdSession* asd)
{
    if (asd)
        return asd->pick_fw_referred_payload_app_id();

    return APP_ID_NONE;
}

bool AppIdApi::is_ssl_session_decrypted(AppIdSession* asd)
{
    if (asd)
        return asd->is_ssl_session_decrypted();

    return false;
}

bool AppIdApi::is_appid_inspecting_session(AppIdSession* asd)
{
    if (asd && asd->common.flow_type == APPID_FLOW_TYPE_NORMAL)
    {
        if (asd->service_disco_state != APPID_DISCO_STATE_FINISHED ||
            !is_third_party_appid_done(asd->tpsession) ||
            asd->get_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE) ||
            (asd->get_session_flags(APPID_SESSION_ENCRYPTED) &&
            (asd->get_session_flags(APPID_SESSION_DECRYPTED) ||
            asd->session_packet_count < SSL_WHITELIST_PKT_LIMIT)))
        {
            return true;
        }

        if (asd->client_disco_state != APPID_DISCO_STATE_FINISHED &&
            (!asd->is_client_detected() ||
            (asd->service_disco_state != APPID_DISCO_STATE_STATEFUL
            && asd->get_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))))
        {
            return true;
        }

        if (asd->tp_app_id == APP_ID_SSH && asd->payload_app_id != APP_ID_SFTP &&
            asd->session_packet_count < MAX_SFTP_PACKET_COUNT)
        {
            return true;
        }
    }

    return false;
}

char* AppIdApi::get_user_name(AppIdSession* asd, AppId* service, bool* isLoginSuccessful)
{
    char* userName = nullptr;
    if (asd)
    {
        userName = asd->username;
        *service = asd->username_service;
        *isLoginSuccessful = asd->get_session_flags(APPID_SESSION_LOGIN_SUCCEEDED) ? true : false;
        //FIXIT-L: what is this ownership transfer about, doesn't smell right...
        asd->username = nullptr; //transfer ownership to caller.
        return userName;
    }
    return nullptr;
}

bool AppIdApi::is_appid_available(AppIdSession* asd)
{
    if (asd)
    {
        if (asd->get_session_flags(APPID_SESSION_NO_TPI))
            return true;
        return is_third_party_appid_available(asd->tpsession);
    }
    return false;
}

char* AppIdApi::get_client_version(AppIdSession* asd)
{
    return asd ? asd->client_version : nullptr;
}

uint64_t AppIdApi::get_appid_session_attribute(AppIdSession* asd, uint64_t flags)
{
    return asd ? asd->get_session_flags(flags) : 0;
}

APPID_FLOW_TYPE AppIdApi::get_flow_type(AppIdSession* asd)
{
    return asd ? asd->common.flow_type : APPID_FLOW_TYPE_IGNORE;
}

void AppIdApi::get_service_info(AppIdSession* asd, char** serviceVendor, char** serviceVersion,
    AppIdServiceSubtype** serviceSubtype)
{
    if (asd)
    {
        *serviceVendor = asd->service_vendor;
        *serviceVersion = asd->service_version;
        *serviceSubtype = asd->subtype;
    }
    else
    {
        *serviceVendor = nullptr;
        *serviceVersion = nullptr;
        *serviceSubtype = nullptr;
    }
}

short AppIdApi::get_service_port(AppIdSession* asd)
{
    if (asd)
        return asd->service_port;
    return 0;
}

char* AppIdApi::get_http_user_agent(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->useragent;
    return nullptr;
}

char* AppIdApi::get_http_host(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->host;
    return nullptr;
}

char* AppIdApi::get_http_url(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->url;
    return nullptr;
}

char* AppIdApi::get_http_referer(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->referer;
    return nullptr;
}

char* AppIdApi::get_http_new_url(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->new_field[REQ_URI_FID];
    return nullptr;
}

char* AppIdApi::get_http_uri(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->uri;
    return nullptr;
}

char* AppIdApi::get_http_response_code(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->response_code;
    return nullptr;
}

char* AppIdApi::get_http_cookie(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->cookie;
    return nullptr;
}

char* AppIdApi::get_http_new_cookie(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->new_field[REQ_COOKIE_FID];
    return nullptr;
}

char* AppIdApi::get_http_new_field(AppIdSession* asd, HTTP_FIELD_ID fieldId)
{
    if (asd && asd->hsession && fieldId >= 0 && fieldId <= HTTP_FIELD_MAX)
        return asd->hsession->new_field[fieldId];
    return nullptr;
}

void AppIdApi::free_http_new_field(AppIdSession* asd, HTTP_FIELD_ID fieldId)
{
    if (asd && asd->hsession && fieldId >= 0 && fieldId <= HTTP_FIELD_MAX &&
        nullptr != asd->hsession->new_field[fieldId])
    {
        snort_free(asd->hsession->new_field[fieldId]);
        asd->hsession->new_field[fieldId] = nullptr;
    }
}

char* AppIdApi::get_http_content_type(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->content_type;
    return nullptr;
}

char* AppIdApi::get_http_location(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->location;
    return nullptr;
}

char* AppIdApi::get_http_body(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->body;
    return nullptr;
}

char* AppIdApi::get_http_request_body(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->req_body;
    return nullptr;
}

uint16_t AppIdApi::get_http_uri_offset(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->fieldOffset[REQ_URI_FID];
    return 0;
}

uint16_t AppIdApi::get_http_uri_end_offset(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->fieldEndOffset[REQ_URI_FID];
    return 0;
}

uint16_t AppIdApi::get_http_cookie_offset(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->fieldOffset[REQ_COOKIE_FID];
    return 0;
}

uint16_t AppIdApi::get_http_cookie_end_offset(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->fieldEndOffset[REQ_COOKIE_FID];
    return 0;
}

SEARCH_SUPPORT_TYPE AppIdApi::get_http_search(AppIdSession* asd)
{
    if (asd)
        return (asd->search_support_type != UNKNOWN_SEARCH_ENGINE) ?
               asd->search_support_type : NOT_A_SEARCH_ENGINE;
    return NOT_A_SEARCH_ENGINE;
}

SfIp* AppIdApi::get_http_xff_addr(AppIdSession* asd)
{
    if (asd && asd->hsession)
        return asd->hsession->xffAddr;
    return nullptr;
}

char* AppIdApi::get_tls_host(AppIdSession* asd)
{
    if (asd && asd->tsession)
        return asd->tsession->tls_host;
    return nullptr;
}

SfIp* AppIdApi::get_service_ip(AppIdSession* asd)
{
    if (asd)
        return &asd->service_ip;
    return nullptr;
}

SfIp* AppIdApi::get_initiator_ip(AppIdSession* asd)
{
    return asd ? &asd->common.initiator_ip : nullptr;
}

DHCPData* AppIdApi::get_dhcp_fp_data(AppIdSession* asd)
{
    if (asd && asd->get_session_flags(APPID_SESSION_HAS_DHCP_FP))
        return static_cast<DHCPData*>(
            asd->remove_flow_data(APPID_SESSION_DATA_DHCP_FP_DATA));

    return nullptr;
}

void AppIdApi::free_dhcp_fp_data(AppIdSession* asd, DHCPData* data)
{
    if (asd)
    {
        asd->clear_session_flags(APPID_SESSION_HAS_DHCP_FP);
        BootpServiceDetector::AppIdFreeDhcpData(data);
    }
}

DHCPInfo* AppIdApi::get_dhcp_info(AppIdSession* asd)
{
    if (asd && asd->get_session_flags(APPID_SESSION_HAS_DHCP_INFO))
        return static_cast<DHCPInfo*>(
            asd->remove_flow_data(APPID_SESSION_DATA_DHCP_INFO));

    return nullptr;
}

void AppIdApi::free_dhcp_info(AppIdSession* asd, DHCPInfo* data)
{
    if (asd)
    {
        asd->clear_session_flags(APPID_SESSION_HAS_DHCP_INFO);
        BootpServiceDetector::AppIdFreeDhcpInfo(data);
    }
}

FpSMBData* AppIdApi::get_smb_fp_data(AppIdSession* asd)
{
    if (asd && asd->get_session_flags(APPID_SESSION_HAS_SMB_INFO))
        return static_cast<FpSMBData*>(
            asd->remove_flow_data(APPID_SESSION_DATA_SMB_DATA));

    return nullptr;
}

void AppIdApi::free_smb_fp_data(AppIdSession* asd, FpSMBData* data)
{
    if (asd)
    {
        asd->clear_session_flags(APPID_SESSION_HAS_SMB_INFO);
        NbdgmServiceDetector::AppIdFreeSMBData(data);
    }
}

char* AppIdApi::get_netbios_name(AppIdSession* asd)
{
    if (asd)
    {
        char* netbiosName = asd->netbios_name;
        asd->netbios_name = nullptr; //transfer ownership to caller.
        return netbiosName;
    }
    return nullptr;
}

#define APPID_HA_FLAGS_APP (1<<0)
#define APPID_HA_FLAGS_TP_DONE (1<<1)
#define APPID_HA_FLAGS_SVC_DONE (1<<2)
#define APPID_HA_FLAGS_HTTP (1<<3)

uint32_t AppIdApi::produce_ha_state(Flow* flow, uint8_t* buf)
{
    assert(flow);
    assert(buf);
    AppIdSessionHA* appHA = (AppIdSessionHA*)buf;
    AppIdSession* asd = (AppIdSession*)(flow->get_flow_data(AppIdSession::inspector_id));

    if ( asd && ( get_flow_type(asd) == APPID_FLOW_TYPE_NORMAL ) )
    {
        appHA->flags = APPID_HA_FLAGS_APP;
        if (is_third_party_appid_available(asd->tpsession))
            appHA->flags |= APPID_HA_FLAGS_TP_DONE;
        if (asd->is_service_detected())
            appHA->flags |= APPID_HA_FLAGS_SVC_DONE;
        if (asd->get_session_flags(APPID_SESSION_HTTP_SESSION))
            appHA->flags |= APPID_HA_FLAGS_HTTP;
        appHA->appId[0] = asd->tp_app_id;
        appHA->appId[1] = asd->service_app_id;
        appHA->appId[2] = asd->client_service_app_id;
        appHA->appId[3] = asd->port_service_id;
        appHA->appId[4] = asd->payload_app_id;
        appHA->appId[5] = asd->tp_payload_app_id;
        appHA->appId[6] = asd->client_app_id;
        appHA->appId[7] = asd->misc_app_id;
    }
    else
        memset(appHA->appId, 0, sizeof(appHA->appId));

    return sizeof(*appHA);
}

uint32_t AppIdApi::consume_ha_state(Flow* flow, const uint8_t* buf, uint8_t, IpProtocol proto,
    SfIp* ip, uint16_t port)
{
    AppIdSessionHA* appHA = (AppIdSessionHA*)buf;
    if (appHA->flags & APPID_HA_FLAGS_APP)
    {
        AppIdSession* asd =
            (AppIdSession*)(flow->get_flow_data(AppIdSession::inspector_id));

        if (!asd)
        {
            asd = new AppIdSession(proto, ip, port);
            flow->set_flow_data(asd);
            asd->service_app_id = appHA->appId[1];
            if (asd->service_app_id == APP_ID_FTP_CONTROL)
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
            if (thirdparty_appid_module)
                thirdparty_appid_module->session_state_set(asd->tpsession, TP_STATE_HA);
        }

        if ( ( appHA->flags & APPID_HA_FLAGS_TP_DONE ) && thirdparty_appid_module )
        {
            thirdparty_appid_module->session_state_set(asd->tpsession, TP_STATE_TERMINATED);
            asd->set_session_flags(APPID_SESSION_NO_TPI);
        }
        if (appHA->flags & APPID_HA_FLAGS_SVC_DONE)
            asd->set_service_detected();
        if (appHA->flags & APPID_HA_FLAGS_HTTP)
            asd->set_session_flags(APPID_SESSION_HTTP_SESSION);

        asd->tp_app_id = appHA->appId[0];
        asd->service_app_id = appHA->appId[1];
        asd->client_service_app_id = appHA->appId[2];
        asd->port_service_id = appHA->appId[3];
        asd->payload_app_id = appHA->appId[4];
        asd->tp_payload_app_id = appHA->appId[5];
        asd->client_app_id = appHA->appId[6];
        asd->misc_app_id = appHA->appId[7];
    }
    return sizeof(*appHA);
}

char* AppIdApi::get_dns_query(AppIdSession* asd, uint8_t* query_len)
{
    if (asd && asd->dsession)
    {
        if (query_len)
        {
            if (asd->dsession->host)
                *query_len = asd->dsession->host_len;

            else
                *query_len = 0;
        }

        return asd->dsession->host;
    }
    if (query_len)
        *query_len = 0;
    return nullptr;
}

uint16_t AppIdApi::get_dns_query_offset(AppIdSession* asd)
{
    if (asd && asd->dsession)
        return asd->dsession->host_offset;
    return 0;
}

uint16_t AppIdApi::get_dns_record_type(AppIdSession* asd)
{
    if (asd && asd->dsession)
        return asd->dsession->record_type;
    return 0;
}

uint8_t AppIdApi::get_dns_response_type(AppIdSession* asd)
{
    if (asd && asd->dsession)
        return asd->dsession->response_type;
    return 0;
}

uint32_t AppIdApi::get_dns_ttl(AppIdSession* asd)
{
    if (asd && asd->dsession)
        return asd->dsession->ttl;
    return 0;
}

bool AppIdApi::is_http_inspection_done(AppIdSession* asd)
{
    bool done = true;

    if ( asd && ( asd->common.flow_type == APPID_FLOW_TYPE_NORMAL ) &&
        !is_third_party_appid_done(asd->tpsession) )
        done = false;

    return done;
}

