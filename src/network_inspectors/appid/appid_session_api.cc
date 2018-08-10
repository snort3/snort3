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

// appid_session_api.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_session_api.h"

#include "appid_session.h"
#include "service_plugins/service_bootp.h"
#include "service_plugins/service_netbios.h"

#define SSL_WHITELIST_PKT_LIMIT 20

using namespace snort;

bool AppIdSessionApi::refresh(Flow& flow)
{
    AppIdSession* new_asd = (AppIdSession*)flow.get_flow_data(AppIdSession::inspector_id);

    if (new_asd and new_asd->common.flow_type == APPID_FLOW_TYPE_NORMAL)
    {
        asd = new_asd;
        return true;
    }
    return false;
}

AppId AppIdSessionApi::get_service_app_id()
{
    return asd->get_application_ids_service();
}

AppId AppIdSessionApi::get_port_service_app_id()
{
    return asd->service.get_port_service_id();
}

AppId AppIdSessionApi::get_only_service_app_id()
{
    return asd->pick_only_service_app_id();
}

AppId AppIdSessionApi::get_misc_app_id()
{
    return asd->get_application_ids_misc();
}

AppId AppIdSessionApi::get_client_app_id()
{
    return asd->get_application_ids_client();
}

AppId AppIdSessionApi::get_payload_app_id()
{
    return asd->get_application_ids_payload();
}

AppId AppIdSessionApi::get_referred_app_id()
{
    return asd->pick_referred_payload_app_id();
}

void AppIdSessionApi::get_app_id(AppId& service, AppId& client,
    AppId& payload, AppId& misc, AppId& referred)
{
    asd->get_application_ids(service, client, payload, misc);
    referred = asd->pick_referred_payload_app_id();
}

void AppIdSessionApi::get_app_id(AppId* service, AppId* client,
    AppId* payload, AppId* misc, AppId* referred)
{
    if (service)
        *service = asd->get_application_ids_service();
    if (client)
        *client = asd->get_application_ids_client();
    if (payload)
        *payload = asd->get_application_ids_payload();
    if (misc)
        *misc = asd->get_application_ids_misc();
    if (referred)
        *referred = asd->pick_referred_payload_app_id();
}

bool AppIdSessionApi::is_ssl_session_decrypted()
{
    return asd->is_ssl_session_decrypted();
}

bool AppIdSessionApi::is_appid_inspecting_session()
{
    if ( asd->service_disco_state != APPID_DISCO_STATE_FINISHED or
        !asd->is_tp_appid_done() or
        asd->get_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE) or
        (asd->get_session_flags(APPID_SESSION_ENCRYPTED) and
            (asd->get_session_flags(APPID_SESSION_DECRYPTED) or
            asd->session_packet_count < SSL_WHITELIST_PKT_LIMIT)) )
    {
        return true;
    }

    if ( asd->client_disco_state != APPID_DISCO_STATE_FINISHED and
        (!asd->is_client_detected() or
            (asd->service_disco_state != APPID_DISCO_STATE_STATEFUL
                and asd->get_session_flags(APPID_SESSION_CLIENT_GETS_SERVER_PACKETS))) )
    {
        return true;
    }

    if ( asd->get_tp_app_id() == APP_ID_SSH and asd->payload.get_id() != APP_ID_SFTP and
        asd->session_packet_count < MAX_SFTP_PACKET_COUNT )
    {
        return true;
    }

    return false;
}

const char* AppIdSessionApi::get_user_name(AppId* service, bool* isLoginSuccessful)
{
    *service = asd->client.get_user_id();
    *isLoginSuccessful = asd->get_session_flags(APPID_SESSION_LOGIN_SUCCEEDED) ? true : false;
    return asd->client.get_username();
}

bool AppIdSessionApi::is_appid_available()
{
    return ( (asd->service.get_id() != APP_ID_NONE ||
        asd->payload.get_id() != APP_ID_NONE) &&
        (asd->is_tp_appid_available() ||
        asd->get_session_flags(APPID_SESSION_NO_TPI)) );
}

const char* AppIdSessionApi::get_client_version()
{
    return asd->client.get_version();
}

uint64_t AppIdSessionApi::get_appid_session_attribute(uint64_t flags)
{
    return asd->get_session_flags(flags);
}

void AppIdSessionApi::get_service_info(const char** vendor, const char** version,
        AppIdServiceSubtype** subtype)
{
    *vendor = asd->service.get_vendor();
    *version = asd->service.get_version();
    *subtype = asd->subtype;
}

short AppIdSessionApi::get_service_port()
{
    return asd->service_port;
}

char* AppIdSessionApi::get_tls_host()
{
    if (asd->tsession)
        return asd->tsession->tls_host;

    return nullptr;
}

SfIp* AppIdSessionApi::get_service_ip()
{
    return &asd->service_ip;
}

SfIp* AppIdSessionApi::get_initiator_ip()
{
    return &asd->common.initiator_ip;
}

DHCPData* AppIdSessionApi::get_dhcp_fp_data()
{
    if (asd->get_session_flags(APPID_SESSION_HAS_DHCP_FP))
        return static_cast<DHCPData*>(asd->remove_flow_data(APPID_SESSION_DATA_DHCP_FP_DATA));

    return nullptr;
}

void AppIdSessionApi::free_dhcp_fp_data(DHCPData* data)
{
    asd->clear_session_flags(APPID_SESSION_HAS_DHCP_FP);
    BootpServiceDetector::AppIdFreeDhcpData(data);
}

DHCPInfo* AppIdSessionApi::get_dhcp_info()
{
    if (asd->get_session_flags(APPID_SESSION_HAS_DHCP_INFO))
        return static_cast<DHCPInfo*>(asd->remove_flow_data(APPID_SESSION_DATA_DHCP_INFO));

    return nullptr;
}

void AppIdSessionApi::free_dhcp_info(DHCPInfo* data)
{
    asd->clear_session_flags(APPID_SESSION_HAS_DHCP_INFO);
    BootpServiceDetector::AppIdFreeDhcpInfo(data);
}

FpSMBData* AppIdSessionApi::get_smb_fp_data()
{
    if (asd->get_session_flags(APPID_SESSION_HAS_SMB_INFO))
        return static_cast<FpSMBData*>(asd->remove_flow_data(APPID_SESSION_DATA_SMB_DATA));

    return nullptr;
}

void AppIdSessionApi::free_smb_fp_data(FpSMBData* data)
{
    asd->clear_session_flags(APPID_SESSION_HAS_SMB_INFO);
    NbdgmServiceDetector::AppIdFreeSMBData(data);
}

const char* AppIdSessionApi::get_netbios_name()
{
    return asd->netbios_name;
}

SEARCH_SUPPORT_TYPE AppIdSessionApi::get_http_search()
{
    return (asd->search_support_type != UNKNOWN_SEARCH_ENGINE) ?
                        asd->search_support_type : NOT_A_SEARCH_ENGINE;
}

AppIdDnsSession* AppIdSessionApi::get_dns_session()
{
    return asd->get_dns_session();
}

AppIdHttpSession* AppIdSessionApi::get_http_session()
{
    return asd->get_http_session();
}

bool AppIdSessionApi::is_http_inspection_done()
{
    return asd->is_tp_appid_done();
}


