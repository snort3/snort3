//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "appid_api.h"

#include "appid.h"
#include "service_plugins/service_base.h"
#include "app_info_table.h"
#include "fw_appid.h"

#include "utils/util.h"

#define SSL_WHITELIST_PKT_LIMIT 20

AppIdApi appid_api;

const char* AppIdApi::get_application_name(int32_t app_id)
{
    return get_app_name(app_id);
}

AppId AppIdApi::get_application_id(const char* appName)
{
    return get_appid_by_name(appName);
}

AppId AppIdApi::get_service_app_id(AppIdSession* session)
{
    if (session)
        return session->pick_service_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_port_service_app_id(AppIdSession* session)
{
    if (session)
        return session->portServiceAppId;
    return APP_ID_NONE;
}

AppId AppIdApi::get_only_service_app_id(AppIdSession* session)
{
    if (session)
        return session->pick_only_service_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_misc_app_id(AppIdSession* session)
{
    if (session)
        return session->pick_misc_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_client_app_id(AppIdSession* session)
{
    if (session)
        return session->pick_client_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_payload_app_id(AppIdSession* session)
{
    if (session)
        return session->pick_payload_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_referred_app_id(AppIdSession* session)
{
    if (session)
        return session->pick_referred_payload_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_fw_service_app_id(AppIdSession* session)
{
    if (session)
        return session->fw_pick_service_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_fw_misc_app_id(AppIdSession* session)
{
    if (session)
        return session->fw_pick_misc_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_fw_client_app_id(AppIdSession* session)
{
    if (session)
        return session->fw_pick_client_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_fw_payload_app_id(AppIdSession* session)
{
    if (session)
        return session->fw_pick_payload_app_id();

    return APP_ID_NONE;
}

AppId AppIdApi::get_fw_referred_app_id(AppIdSession* session)
{
    if (session)
        return session->fw_pick_referred_payload_app_id();

    return APP_ID_NONE;
}

bool AppIdApi::is_ssl_session_decrypted(AppIdSession* session)
{
    if (session)
        return session->is_ssl_session_decrypted();

    return false;
}

AppIdSession* AppIdApi::get_appid_data(Flow* flow)
{
    AppIdSession* session = (AppIdSession*) flow->get_flow_data(AppIdSession::flow_id);

    return (session && session->common.fsf_type.flow_type == APPID_SESSION_TYPE_NORMAL) ?
           session : nullptr;
}

bool AppIdApi::is_appid_inspecting_session(AppIdSession* appIdSession)
{
    if (appIdSession && appIdSession->common.fsf_type.flow_type == APPID_SESSION_TYPE_NORMAL)
    {
        if (appIdSession->rnaServiceState != RNA_STATE_FINISHED ||
            !TPIsAppIdDone(appIdSession->tpsession) ||
            appIdSession->getAppIdFlag(APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE) ||
                (appIdSession->getAppIdFlag(APPID_SESSION_ENCRYPTED) &&
                        (appIdSession->getAppIdFlag(APPID_SESSION_DECRYPTED) ||
                         appIdSession->session_packet_count < SSL_WHITELIST_PKT_LIMIT)))
        {
            return true;
        }
        if (appIdSession->rna_client_state != RNA_STATE_FINISHED &&
            (!appIdSession->getAppIdFlag(APPID_SESSION_CLIENT_DETECTED) ||
            (appIdSession->rnaServiceState != RNA_STATE_STATEFUL
                    && appIdSession->getAppIdFlag(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))))
        {
            return true;
        }
        if (appIdSession->tp_app_id == APP_ID_SSH && appIdSession->payload_app_id != APP_ID_SFTP &&
            appIdSession->session_packet_count < MAX_SFTP_PACKET_COUNT)
        {
            return true;
        }
    }
    return false;
}

char* AppIdApi::get_user_name(AppIdSession* session, AppId* service, bool* isLoginSuccessful)
{
    char* userName = nullptr;
    if (session)
    {
        userName = session->username;
        *service = session->username_service;
        *isLoginSuccessful = session->getAppIdFlag(APPID_SESSION_LOGIN_SUCCEEDED) ? true : false;
        session->username = nullptr; //transfer ownership to caller.
        return userName;
    }
    return nullptr;
}

bool AppIdApi::is_appid_available(AppIdSession* session)
{
    if (session)
    {
        if (session->getAppIdFlag(APPID_SESSION_NO_TPI))
            return true;
        return TPIsAppIdAvailable(session->tpsession);
    }
    return false;
}

char* AppIdApi::get_client_version(AppIdSession* session)
{
    return session ? session->client_version : nullptr;
}

uint64_t AppIdApi::get_appid_session_attribute(AppIdSession* session, uint64_t flags)
{
    return session ? session->getAppIdFlag(flags) : 0;
}

APPID_FLOW_TYPE AppIdApi::get_flow_type(AppIdSession* session)
{
    return session ? session->common.fsf_type.flow_type : APPID_FLOW_TYPE_IGNORE;
}

void AppIdApi::get_service_info(AppIdSession* session, char** serviceVendor, char** serviceVersion,
    RNAServiceSubtype** serviceSubtype)
{
    if (session)
    {
        *serviceVendor = session->serviceVendor;
        *serviceVersion = session->serviceVersion;
        *serviceSubtype = session->subtype;
    }
    else
    {
        *serviceVendor = nullptr;
        *serviceVersion = nullptr;
        *serviceSubtype = nullptr;
    }
}

short AppIdApi::get_service_port(AppIdSession* session)
{
    if (session)
        return session->service_port;
    return 0;
}

char* AppIdApi::get_http_user_agent(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->useragent;
    return nullptr;
}

char* AppIdApi::get_http_host(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->host;
    return nullptr;
}

char* AppIdApi::get_http_url(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->url;
    return nullptr;
}

char* AppIdApi::get_http_referer(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->referer;
    return nullptr;
}

char* AppIdApi::get_http_new_url(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->new_field[REQ_URI_FID];
    return nullptr;
}

char* AppIdApi::get_http_uri(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->uri;
    return nullptr;
}

char* AppIdApi::get_http_response_code(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->response_code;
    return nullptr;
}

char* AppIdApi::get_http_cookie(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->cookie;
    return nullptr;
}

char* AppIdApi::get_http_new_cookie(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->new_field[REQ_COOKIE_FID];
    return nullptr;
}

char* AppIdApi::get_http_new_field(AppIdSession* session, HTTP_FIELD_ID fieldId)
{
    if (session && session->hsession && fieldId >= 0 && fieldId <= HTTP_FIELD_MAX)
        return session->hsession->new_field[fieldId];
    return nullptr;
}

void AppIdApi::free_http_new_field(AppIdSession* session, HTTP_FIELD_ID fieldId)
{
    if (session && session->hsession && fieldId >= 0 && fieldId <= HTTP_FIELD_MAX &&
        nullptr != session->hsession->new_field[fieldId])
    {
        snort_free(session->hsession->new_field[fieldId]);
        session->hsession->new_field[fieldId] = nullptr;
    }
}

char* AppIdApi::get_http_content_type(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->content_type;
    return nullptr;
}

char* AppIdApi::get_http_location(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->location;
    return nullptr;
}

char* AppIdApi::get_http_body(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->body;
    return nullptr;
}

char* AppIdApi::get_http_request_body(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->req_body;
    return nullptr;
}

uint16_t AppIdApi::get_http_uri_offset(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->uriOffset;
    return 0;
}

uint16_t AppIdApi::get_http_uri_end_offset(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->uriEndOffset;
    return 0;
}

uint16_t AppIdApi::get_http_cookie_offset(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->cookieOffset;
    return 0;
}

uint16_t AppIdApi::get_http_cookie_end_offset(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->cookieEndOffset;
    return 0;
}

SEARCH_SUPPORT_TYPE AppIdApi::get_http_search(AppIdSession* session)
{
    if (session)
        return (session->search_support_type != SEARCH_SUPPORT_TYPE_UNKNOWN) ?
               session->search_support_type : NOT_A_SEARCH_ENGINE;
    return NOT_A_SEARCH_ENGINE;
}

// FIXIT used to be sfaddr_t
sfip_t* AppIdApi::get_http_xff_addr(AppIdSession* session)
{
    if (session && session->hsession)
        return session->hsession->xffAddr;
    return nullptr;
}

char* AppIdApi::get_tls_host(AppIdSession* session)
{
    if (session && session->tsession)
        return session->tsession->tls_host;
    return nullptr;
}

// FIXIT used to be sfaddr_t
sfip_t* AppIdApi::get_service_ip(AppIdSession* session)
{
    if (session)
        return &session->service_ip;
    return nullptr;
}

// FIXIT used to be sfaddr_t
sfip_t* AppIdApi::get_initiator_ip(AppIdSession* session)
{
    return session ? &session->common.initiator_ip : nullptr;
}

DhcpFPData* AppIdApi::get_dhcp_fp_data(AppIdSession* session)
{
    if (session && session->getAppIdFlag(APPID_SESSION_HAS_DHCP_FP))
        return static_cast<DhcpFPData*>(
            session->remove_flow_data(APPID_SESSION_DATA_DHCP_FP_DATA));

    return nullptr;
}

void AppIdApi::free_dhcp_fp_data(AppIdSession* session, DhcpFPData* data)
{
    if (session)
    {
        session->clearAppIdFlag(APPID_SESSION_HAS_DHCP_FP);
        AppIdFreeDhcpData(data);
    }
}

DHCPInfo* AppIdApi::get_dhcp_info(AppIdSession* session)
{
    if (session && session->getAppIdFlag(APPID_SESSION_HAS_DHCP_INFO))
        return static_cast<DHCPInfo*>(
            session->remove_flow_data(APPID_SESSION_DATA_DHCP_INFO));

    return nullptr;
}

void AppIdApi::free_dhcp_info(AppIdSession* session, DHCPInfo* data)
{
    if (session)
    {
        session->clearAppIdFlag(APPID_SESSION_HAS_DHCP_INFO);
        AppIdFreeDhcpInfo(data);
    }
}

FpSMBData* AppIdApi::get_smb_fp_data(AppIdSession* session)
{
    if (session && session->getAppIdFlag(APPID_SESSION_HAS_SMB_INFO))
        return static_cast<FpSMBData*>(
            session->remove_flow_data(APPID_SESSION_DATA_SMB_DATA));

    return nullptr;
}

void AppIdApi::free_smb_fp_data(AppIdSession* session, FpSMBData* data)
{
    if (session)
    {
        session->clearAppIdFlag(APPID_SESSION_HAS_SMB_INFO);
        AppIdFreeSMBData(data);
    }
}

char* AppIdApi::get_netbios_name(AppIdSession* session)
{
    if (session)
    {
        char* netbiosName = session->netbios_name;
        session->netbios_name = nullptr; //transfer ownership to caller.
        return netbiosName;
    }
    return nullptr;
}

#define APPID_HA_FLAGS_APP (1<<0)
#define APPID_HA_FLAGS_TP_DONE (1<<1)
#define APPID_HA_FLAGS_SVC_DONE (1<<2)
#define APPID_HA_FLAGS_HTTP (1<<3)

uint32_t AppIdApi::produce_ha_state(void* lwssn, uint8_t* buf)
{
    AppIdSessionHA* appHA = (AppIdSessionHA*)buf;
    AppIdSession* session = (AppIdSession*)(((Flow*)lwssn)->get_flow_data(AppIdSession::flow_id));

    // FIXIT - getFlowType should be a class member
    if (session && get_flow_type(session) != APPID_FLOW_TYPE_NORMAL)
        session = nullptr;
    if (session)
    {
        appHA->flags = APPID_HA_FLAGS_APP;
        if (TPIsAppIdAvailable(session->tpsession))
            appHA->flags |= APPID_HA_FLAGS_TP_DONE;
        if (session->getAppIdFlag(APPID_SESSION_SERVICE_DETECTED))
            appHA->flags |= APPID_HA_FLAGS_SVC_DONE;
        if (session->getAppIdFlag(APPID_SESSION_HTTP_SESSION))
            appHA->flags |= APPID_HA_FLAGS_HTTP;
        appHA->appId[0] = session->tp_app_id;
        appHA->appId[1] = session->serviceAppId;
        appHA->appId[2] = session->client_service_app_id;
        appHA->appId[3] = session->portServiceAppId;
        appHA->appId[4] = session->payload_app_id;
        appHA->appId[5] = session->tp_payload_app_id;
        appHA->appId[6] = session->client_app_id;
        appHA->appId[7] = session->misc_app_id;
    }
    else
    {
        memset(appHA->appId, 0, sizeof(appHA->appId));
    }
    return sizeof(*appHA);
}

// FIXIT last arg used to be sfaddr_t
uint32_t AppIdApi::consume_ha_state(void* lwssn, const uint8_t* buf, uint8_t, IpProtocol proto,
    sfip_t* ip)
{
    AppIdSessionHA* appHA = (AppIdSessionHA*)buf;
    if (appHA->flags & APPID_HA_FLAGS_APP)
    {
        AppIdSession* session = (AppIdSession*)(((Flow*)lwssn)->get_flow_data(
            AppIdSession::flow_id));

        if (!session)
        {
            session = new AppIdSession(proto, ip);
            ((Flow*)lwssn)->set_flow_data(session);
            if (session->serviceAppId == APP_ID_FTP_CONTROL)
            {
                session->setAppIdFlag(APPID_SESSION_CLIENT_DETECTED |
                    APPID_SESSION_NOT_A_SERVICE | APPID_SESSION_SERVICE_DETECTED);
                if (!AddFTPServiceState(session))
                {
                    session->setAppIdFlag(APPID_SESSION_CONTINUE);
                }
                session->rnaServiceState = RNA_STATE_STATEFUL;
            }
            else
                session->rnaServiceState = RNA_STATE_FINISHED;
            session->rna_client_state = RNA_STATE_FINISHED;
            if (thirdparty_appid_module)
                thirdparty_appid_module->session_state_set(session->tpsession, TP_STATE_HA);
        }

        if ( ( appHA->flags & APPID_HA_FLAGS_TP_DONE ) && thirdparty_appid_module )
        {
            thirdparty_appid_module->session_state_set(session->tpsession, TP_STATE_TERMINATED);
            session->setAppIdFlag(APPID_SESSION_NO_TPI);
        }
        if (appHA->flags & APPID_HA_FLAGS_SVC_DONE)
            session->setAppIdFlag(APPID_SESSION_SERVICE_DETECTED);
        if (appHA->flags & APPID_HA_FLAGS_HTTP)
            session->setAppIdFlag(APPID_SESSION_HTTP_SESSION);

        session->tp_app_id = appHA->appId[0];
        session->serviceAppId = appHA->appId[1];
        session->client_service_app_id = appHA->appId[2];
        session->portServiceAppId = appHA->appId[3];
        session->payload_app_id = appHA->appId[4];
        session->tp_payload_app_id = appHA->appId[5];
        session->client_app_id = appHA->appId[6];
        session->misc_app_id = appHA->appId[7];
    }
    return sizeof(*appHA);
}

char* AppIdApi::get_dns_query(AppIdSession* session, uint8_t* query_len)
{
    if (session && session->dsession)
    {
        if (query_len)
        {
            if (session->dsession->host)
                *query_len = session->dsession->host_len;

            else
                *query_len = 0;
        }

        return session->dsession->host;
    }
    if (query_len)
        *query_len = 0;
    return nullptr;
}

uint16_t AppIdApi::get_dns_query_offset(AppIdSession* session)
{
    if (session && session->dsession)
        return session->dsession->host_offset;
    return 0;
}

uint16_t AppIdApi::get_dns_record_type(AppIdSession* session)
{
    if (session && session->dsession)
        return session->dsession->record_type;
    return 0;
}

uint8_t AppIdApi::get_dns_response_type(AppIdSession* session)
{
    if (session && session->dsession)
        return session->dsession->response_type;
    return 0;
}

uint32_t AppIdApi::get_dns_ttl(AppIdSession* session)
{
    if (session && session->dsession)
        return session->dsession->ttl;
    return 0;
}

