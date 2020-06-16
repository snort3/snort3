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

bool AppIdSessionApi::refresh(const Flow& flow)
{
    AppIdSession* new_asd = (AppIdSession*)flow.get_flow_data(AppIdSession::inspector_id);

    if (new_asd)
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

AppId AppIdSessionApi::get_misc_app_id(uint32_t stream_index)
{
    return asd->get_application_ids_misc(stream_index);
}

AppId AppIdSessionApi::get_client_app_id(uint32_t stream_index)
{
    return asd->get_application_ids_client(stream_index);
}

AppId AppIdSessionApi::get_payload_app_id(uint32_t stream_index)
{
    return asd->get_application_ids_payload(stream_index);
}

AppId AppIdSessionApi::get_referred_app_id(uint32_t stream_index)
{
    if (asd->get_application_ids_service() == APP_ID_HTTP2)
    {
        if ((stream_index != 0) and (stream_index >= asd->get_hsessions_size()))
            return APP_ID_UNKNOWN;
        else if (AppIdHttpSession* hsession = asd->get_http_session(stream_index))
            return hsession->referred_payload_app_id;
    }
    else if (stream_index == 0)
        return asd->pick_ss_referred_payload_app_id();

    return APP_ID_UNKNOWN;
}

void AppIdSessionApi::get_app_id(AppId& service, AppId& client,
    AppId& payload, AppId& misc, AppId& referred, uint32_t stream_index)
{
    if (asd->get_application_ids_service() == APP_ID_HTTP2)
    {
        if ((stream_index != 0) and (stream_index >= asd->get_hsessions_size()))
            service = client = payload = misc = referred = APP_ID_UNKNOWN;
        else if (AppIdHttpSession* hsession = asd->get_http_session(stream_index))
        {
            service = asd->get_application_ids_service();
            client = hsession->client.get_id();
            payload = hsession->payload.get_id();
            misc = hsession->misc_app_id;
            referred = hsession->referred_payload_app_id;
        }
    }
    else
    {
        asd->get_first_stream_app_ids(service, client, payload, misc);
        referred = asd->pick_ss_referred_payload_app_id();
    }
}

void AppIdSessionApi::get_app_id(AppId* service, AppId* client,
    AppId* payload, AppId* misc, AppId* referred, uint32_t stream_index)
{
    if (asd->get_application_ids_service() == APP_ID_HTTP2)
    {
        if ((stream_index != 0) and (stream_index >= asd->get_hsessions_size()))
        {
            if (service)
                *service = APP_ID_UNKNOWN;
            if (client)
                *client = APP_ID_UNKNOWN;
            if (payload)
                *payload = APP_ID_UNKNOWN;
            if (misc)
                *misc = APP_ID_UNKNOWN;
            if (referred)
                *referred = APP_ID_UNKNOWN;
            return;
        }
        else if (AppIdHttpSession* hsession = asd->get_http_session(stream_index))
        {
            if (service)
                *service = asd->get_application_ids_service();
            if (client)
                *client = hsession->client.get_id();
            if (payload)
                *payload = hsession->payload.get_id();
            if (misc)
                *misc = hsession->misc_app_id;
            if (referred)
                *referred = hsession->referred_payload_app_id;
            return;
        }
    }
    if (service)
        *service = asd->get_application_ids_service();
    if (client)
        *client = asd->get_application_ids_client();
    if (payload)
        *payload = asd->get_application_ids_payload();
    if (misc)
        *misc = asd->get_application_ids_misc();
    if (referred)
        *referred = asd->pick_ss_referred_payload_app_id();
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

    if (asd->ctxt.get_odp_ctxt().check_host_port_app_cache)
        return true;

    return false;
}

bool AppIdSessionApi::is_appid_available()
{
    return ( (asd->service.get_id() != APP_ID_NONE ||
        asd->payload.get_id() != APP_ID_NONE) &&
        (asd->is_tp_appid_available() ||
        asd->get_session_flags(APPID_SESSION_NO_TPI)) );
}

const char* AppIdSessionApi::get_client_version(uint32_t stream_index)
{
    if (uint32_t num_hsessions = asd->get_hsessions_size())
    {
        if (stream_index >= num_hsessions)
            return nullptr;
        else if (AppIdHttpSession* hsession = asd->get_http_session(stream_index))
            return hsession->client.get_version();
    }
    else if (stream_index == 0)
        return asd->client.get_version();

    return nullptr;
}

uint64_t AppIdSessionApi::get_appid_session_attribute(uint64_t flags)
{
    return asd->get_session_flags(flags);
}

const char* AppIdSessionApi::get_tls_host()
{
    if (asd->tsession)
        return asd->tsession->get_tls_host();
    return nullptr;
}

SfIp* AppIdSessionApi::get_initiator_ip()
{
    return &asd->common.initiator_ip;
}

AppIdDnsSession* AppIdSessionApi::get_dns_session()
{
    return asd->get_dns_session();
}

AppIdHttpSession* AppIdSessionApi::get_http_session(uint32_t stream_index)
{
    return asd->get_http_session(stream_index);
}

bool AppIdSessionApi::is_http_inspection_done()
{
    return (asd->is_tp_appid_done() and
           !(asd->get_session_flags(APPID_SESSION_SSL_SESSION) and
               !get_tls_host() and
               (asd->service_disco_state!= APPID_DISCO_STATE_FINISHED)));
}
