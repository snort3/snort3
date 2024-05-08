//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "flow/ha.h"
#include "appid_inspector.h"
#include "appid_peg_counts.h"
#include "appid_session.h"
#include "appid_types.h"
#include "service_plugins/service_bootp.h"
#include "service_plugins/service_netbios.h"

#define SSL_ALLOWLIST_PKT_LIMIT 20

using namespace snort;

static THREAD_LOCAL uint32_t appid_flow_data_id = 0;

AppIdSessionApi::AppIdSessionApi(const AppIdSession* asd, const SfIp& ip) :
    StashGenericObject(STASH_GENERIC_OBJECT_APPID), asd(asd), initiator_ip(ip),
    session_id(std::to_string(get_instance_id()) + "." + std::to_string(++appid_flow_data_id))
{ }

AppId AppIdSessionApi::get_service_app_id() const
{
    return application_ids[APP_PROTOID_SERVICE];
}

void AppIdSessionApi::get_service_info(const char*& vendor, const char*& version,
    const AppIdServiceSubtype*& subtype) const
{
    vendor = service.get_vendor();
    version = service.get_version();
    subtype = service.get_subtype();
}

const char* AppIdSessionApi::get_user_info(AppId& service, bool& login) const
{
    service = client.get_user_id();
    login = flags.user_logged_in;
    return client.get_username();
}

AppId AppIdSessionApi::get_misc_app_id(uint32_t stream_index) const
{
    if (get_service_app_id() == APP_ID_HTTP2 or get_service_app_id() == APP_ID_HTTP3)
    {
        if ((stream_index != 0) and (stream_index >= get_hsessions_size()))
            return APP_ID_NONE;
        else if (AppIdHttpSession* hsession = get_hsession(stream_index))
            return hsession->misc_app_id;
        else if ((get_service_app_id() == APP_ID_HTTP3) and (stream_index == 0))
            return application_ids[APP_PROTOID_MISC];
    }
    else if (stream_index == 0)
        return application_ids[APP_PROTOID_MISC];

    return APP_ID_NONE;
}

bool AppIdSessionApi::prefer_eve_client_over_appid_http_client() const
{
    return ((client.get_eve_client_app_id() > APP_ID_NONE) and pkt_thread_odp_ctxt
        and pkt_thread_odp_ctxt->eve_http_client);
}

AppId AppIdSessionApi::get_client_app_id(uint32_t stream_index) const
{
    AppId service_id = get_service_app_id();
    if (service_id == APP_ID_HTTP2 or service_id == APP_ID_HTTP3)
    {
        if ((stream_index != 0) and (stream_index >= get_hsessions_size()))
            return APP_ID_NONE;
        else if (service_id == APP_ID_HTTP2 and prefer_eve_client_over_appid_http_client())
            return application_ids[APP_PROTOID_CLIENT];
        else if (AppIdHttpSession* hsession = get_hsession(stream_index))
            return hsession->client.get_id();
        else if ((get_service_app_id() == APP_ID_HTTP3) and (stream_index == 0))
            return application_ids[APP_PROTOID_CLIENT];
    }
    else if (stream_index == 0)
        return application_ids[APP_PROTOID_CLIENT];

    return APP_ID_NONE;
}

AppId AppIdSessionApi::get_payload_app_id(uint32_t stream_index) const
{
    if (get_service_app_id() == APP_ID_HTTP2 or get_service_app_id() == APP_ID_HTTP3)
    {
        if ((stream_index != 0) and (stream_index >= get_hsessions_size()))
            return APP_ID_NONE;
        else if (AppIdHttpSession* hsession = get_hsession(stream_index))
            return hsession->payload.get_id();
        else if ((get_service_app_id() == APP_ID_HTTP3) and (stream_index == 0))
            return application_ids[APP_PROTOID_PAYLOAD];
    }
    else if (stream_index == 0)
        return application_ids[APP_PROTOID_PAYLOAD];

    return APP_ID_NONE;
}

AppId AppIdSessionApi::get_referred_app_id(uint32_t stream_index) const
{
    if (get_service_app_id() == APP_ID_HTTP2 or get_service_app_id() == APP_ID_HTTP3)
    {
        if ((stream_index != 0) and (stream_index >= get_hsessions_size()))
            return APP_ID_UNKNOWN;
        else if (AppIdHttpSession* hsession = get_hsession(stream_index))
            return hsession->referred_payload_app_id;
    }
    else if (stream_index == 0)
        return application_ids[APP_PROTOID_REFERRED];

    return APP_ID_NONE;
}

void AppIdSessionApi::get_app_id(AppId& service, AppId& client,
    AppId& payload, AppId& misc, AppId& referred, uint32_t stream_index) const
{
    AppId service_id = get_service_app_id();
    if (service_id == APP_ID_HTTP2 or service_id == APP_ID_HTTP3)
    {
        if ((stream_index != 0) and (stream_index >= get_hsessions_size()))
        {
            service = client = payload = misc = referred = APP_ID_UNKNOWN;
            return;
        }
        else if (AppIdHttpSession* hsession = get_hsession(stream_index))
        {
            service = service_id;
            if (service_id == APP_ID_HTTP2 and prefer_eve_client_over_appid_http_client())
                client = application_ids[APP_PROTOID_CLIENT];
            else
                client = hsession->client.get_id();
            payload = hsession->payload.get_id();
            misc = hsession->misc_app_id;
            referred = hsession->referred_payload_app_id;
            return;
        }
    }

    get_first_stream_app_ids(service, client, payload, misc);
    referred = get_referred_app_id();
}

void AppIdSessionApi::get_app_id(AppId* service, AppId* client,
    AppId* payload, AppId* misc, AppId* referred, uint32_t stream_index) const
{
    AppId service_id = get_service_app_id();
    if (service_id == APP_ID_HTTP2 or service_id == APP_ID_HTTP3)
    {
        if ((stream_index != 0) and (stream_index >= get_hsessions_size()))
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
        else if (AppIdHttpSession* hsession = get_hsession(stream_index))
        {
            if (service)
                *service = service_id;
            if (client)
            {
                if (service_id == APP_ID_HTTP2 and prefer_eve_client_over_appid_http_client())
                    *client = application_ids[APP_PROTOID_CLIENT];
                else
                    *client = hsession->client.get_id();
            }
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
        *service = service_id;
    if (client)
    {
        if (service_id == APP_ID_HTTP2 and prefer_eve_client_over_appid_http_client())
            *client = application_ids[APP_PROTOID_CLIENT];
        else
            *client = get_client_app_id();
    }
    if (payload)
        *payload = get_payload_app_id();
    if (misc)
        *misc = get_misc_app_id();
    if (referred)
        *referred = get_referred_app_id();
}

bool AppIdSessionApi::is_appid_inspecting_session() const
{
    if (!asd)
        return false;
    else
    {
        // Inspection is not done for sessions using old odp context after reload detectors
        if (!pkt_thread_odp_ctxt or
            (pkt_thread_odp_ctxt->get_version() != asd->get_odp_ctxt_version()))
            return false;
    }

    if ( (get_service_app_id() == APP_ID_QUIC or  get_service_app_id() == APP_ID_HTTP3) and
         !asd->get_session_flags(APPID_SESSION_DECRYPTED) )
        return false;

    if ( asd->service_disco_state != APPID_DISCO_STATE_FINISHED or
        !asd->is_tp_appid_done() or
        asd->get_session_flags(APPID_SESSION_HTTP_SESSION | APPID_SESSION_CONTINUE) or
        (asd->get_session_flags(APPID_SESSION_ENCRYPTED) and
            (asd->get_session_flags(APPID_SESSION_DECRYPTED) or
            asd->session_packet_count < SSL_ALLOWLIST_PKT_LIMIT)) )
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

    if ( get_service_app_id() == APP_ID_SSH and get_payload_app_id() != APP_ID_SFTP and
        asd->session_packet_count < MAX_SFTP_PACKET_COUNT )
    {
        return true;
    }

    if ( get_service_app_id() == APP_ID_CIP)
    {
         return true;
    }

    if (asd->get_odp_ctxt().check_host_port_app_cache)
        return true;

    return false;
}

bool AppIdSessionApi::is_appid_available(uint32_t stream_index) const
{
    if (!asd)
        return false;
    if (service.get_id() == APP_ID_HTTP2 or service.get_id() == APP_ID_HTTP3)
        return (get_payload_app_id(stream_index) != APP_ID_NONE);
    else
        return (service.get_id() != APP_ID_NONE or
            payload.get_id() != APP_ID_NONE);
}

const char* AppIdSessionApi::get_client_info(uint32_t stream_index) const
{
    if (uint32_t num_hsessions = get_hsessions_size())
    {
        if (stream_index >= num_hsessions)
            return nullptr;
        else if (AppIdHttpSession* hsession = get_hsession(stream_index))
        {
            if (prefer_eve_client_over_appid_http_client())
            {
                if (hsession->client.get_id() == client.get_eve_client_app_id())
                    return hsession->client.get_version();
                else
                    return nullptr;
            }
            else
                return hsession->client.get_version();
        }
    }
    else if (stream_index == 0)
        return client.get_version();

    return nullptr;
}

uint64_t AppIdSessionApi::get_appid_session_attribute(uint64_t flags) const
{
    if (!asd)
        return 0;

    return asd->get_session_flags(flags);
}

const char* AppIdSessionApi::get_tls_host() const
{
    return tls_host;
}

const SfIp* AppIdSessionApi::get_initiator_ip() const
{
    return &initiator_ip;
}

const SfIp& AppIdSessionApi::get_service_ip() const
{
    return service.get_service_ip();
}

uint16_t AppIdSessionApi::get_service_port() const
{
    return service.get_service_port();
}

const AppIdDnsSession* AppIdSessionApi::get_dns_session() const
{
    return dsession;
}

bool AppIdSessionApi::is_http_inspection_done() const
{
    if (!asd)
        return true;

    return (asd->is_tp_appid_done() and
        !(asd->get_session_flags(APPID_SESSION_SSL_SESSION) and !get_tls_host() and
            (asd->service_disco_state!= APPID_DISCO_STATE_FINISHED)));
}

const char* AppIdSessionApi::get_netbios_name() const
{
    return netbios_name;
}

const char* AppIdSessionApi::get_netbios_domain() const
{
    return netbios_domain;
}

ClientAppDetectType AppIdSessionApi::get_client_app_detect_type() const
{
    return client.get_client_app_detect_type();
}

void AppIdSessionApi::set_netbios_name(AppidChangeBits& change_bits, const char* name)
{
    if (netbios_name)
    {
        if (strcmp(netbios_name, name) == 0)
            return;
        snort_free(netbios_name);
    }
    netbios_name = snort_strdup(name);
    change_bits.set(APPID_NETBIOS_NAME_BIT);
}

void AppIdSessionApi::set_netbios_domain(AppidChangeBits& change_bits, const char* domain)
{
    if (netbios_domain)
    {
        if (strcmp(netbios_domain, domain) == 0)
            return;
        snort_free(netbios_domain);
    }
    netbios_domain = snort_strdup(domain);
    change_bits.set(APPID_NETBIOS_DOMAIN_BIT);
}

void AppIdSessionApi::set_ss_application_ids(AppId service_id, AppId client_id,
    AppId payload_id, AppId misc_id, AppId referred_id, AppidChangeBits& change_bits, Flow& flow)
{
    set_application_ids_service(service_id, change_bits, flow);
    set_ss_application_ids(client_id, payload_id, change_bits, flow);

    if (application_ids[APP_PROTOID_MISC] != misc_id)
    {
        application_ids[APP_PROTOID_MISC] = misc_id;
        AppIdPegCounts::inc_misc_count(misc_id);
        change_bits.set(APPID_MISC_BIT);
        if (flow.ha_state)
            flow.ha_state->add(FlowHAState::MODIFIED | FlowHAState::MAJOR);
    }
    if (application_ids[APP_PROTOID_REFERRED] != referred_id)
    {
        application_ids[APP_PROTOID_REFERRED] = referred_id;
        AppIdPegCounts::inc_referred_count(referred_id);
        change_bits.set(APPID_REFERRED_BIT);
    }
}

void AppIdSessionApi::set_ss_application_ids_payload(AppId payload_id,
    AppidChangeBits& change_bits, Flow& flow)
{
    if (application_ids[APP_PROTOID_PAYLOAD] != payload_id)
    {
        application_ids[APP_PROTOID_PAYLOAD] = payload_id;
        AppIdPegCounts::inc_payload_count(payload_id);
        change_bits.set(APPID_PAYLOAD_BIT);
        if (flow.ha_state)
            flow.ha_state->add(FlowHAState::MODIFIED | FlowHAState::MAJOR);
    }
}

void AppIdSessionApi::set_ss_application_ids(AppId client_id, AppId payload_id,
    AppidChangeBits& change_bits, Flow& flow)
{
    if (application_ids[APP_PROTOID_CLIENT] != client_id)
    {
        application_ids[APP_PROTOID_CLIENT] = client_id;
        AppIdPegCounts::inc_client_count(client_id);
        change_bits.set(APPID_CLIENT_BIT);
        if (flow.ha_state)
            flow.ha_state->add(FlowHAState::MODIFIED | FlowHAState::MAJOR);
    }
    set_ss_application_ids_payload(payload_id, change_bits, flow);
}

void AppIdSessionApi::set_application_ids_service(AppId service_id, AppidChangeBits& change_bits,
    Flow& flow)
{
    if (application_ids[APP_PROTOID_SERVICE] != service_id)
    {
        application_ids[APP_PROTOID_SERVICE] = service_id;
        AppIdPegCounts::inc_service_count(service_id);
        change_bits.set(APPID_SERVICE_BIT);
        if (flow.ha_state)
            flow.ha_state->add(FlowHAState::MODIFIED | FlowHAState::MAJOR);
    }
}

// For HTTP3, mercury can identify client,payload and misc. So check for them
// even if no hsession is present, but prefer appid stored in hsession.
void AppIdSessionApi::get_first_stream_app_ids(AppId& service_id, AppId& client_id,
    AppId& payload_id, AppId& misc_id) const
{
    service_id = application_ids[APP_PROTOID_SERVICE];
    if (service_id != APP_ID_HTTP2 and service_id != APP_ID_HTTP3)
    {
        client_id  = application_ids[APP_PROTOID_CLIENT];
        payload_id = application_ids[APP_PROTOID_PAYLOAD];
        misc_id    = application_ids[APP_PROTOID_MISC];
    }
    else if (AppIdHttpSession* hsession = get_hsession(0))
    {
        if (service_id == APP_ID_HTTP2 and prefer_eve_client_over_appid_http_client())
            client_id = application_ids[APP_PROTOID_CLIENT];
        else
            client_id = hsession->client.get_id();
        payload_id = hsession->payload.get_id();
        misc_id = hsession->misc_app_id;
    }
    else if (service_id == APP_ID_HTTP3)
    {
        client_id  = application_ids[APP_PROTOID_CLIENT];
        payload_id = application_ids[APP_PROTOID_PAYLOAD];
        misc_id    = application_ids[APP_PROTOID_MISC];
    }
    else
    {
        client_id = APP_ID_NONE;
        payload_id = APP_ID_NONE;
        misc_id = APP_ID_NONE;
    }
}

void AppIdSessionApi::get_first_stream_app_ids(AppId& service_id, AppId& client_id,
    AppId& payload_id) const
{
    service_id = application_ids[APP_PROTOID_SERVICE];
    if (service_id != APP_ID_HTTP2 and service_id != APP_ID_HTTP3)
    {
        client_id  = application_ids[APP_PROTOID_CLIENT];
        payload_id = application_ids[APP_PROTOID_PAYLOAD];
    }
    else if (AppIdHttpSession* hsession = get_hsession(0))
    {
        if (service_id == APP_ID_HTTP2 and prefer_eve_client_over_appid_http_client())
            client_id = application_ids[APP_PROTOID_CLIENT];
        else
            client_id = hsession->client.get_id();
        payload_id = hsession->payload.get_id();
    }
    else if (service_id == APP_ID_HTTP3)
    {
        client_id  = application_ids[APP_PROTOID_CLIENT];
        payload_id = application_ids[APP_PROTOID_PAYLOAD];
    }
    else
    {
        client_id = APP_ID_NONE;
        payload_id = APP_ID_NONE;
    }
}

const AppIdHttpSession* AppIdSessionApi::get_http_session(uint32_t stream_index) const
{
    return get_hsession(stream_index);
}

const AppIdHttpSession* AppIdSessionApi::get_matching_http_session(int64_t stream_id) const
{
    for (uint32_t stream_index=0; stream_index < hsessions.size(); stream_index++)
    {
        if(stream_id == hsessions[stream_index]->get_httpx_stream_id())
            return hsessions[stream_index];
    }
    return nullptr;
}

AppIdHttpSession* AppIdSessionApi::get_hsession(uint32_t stream_index) const
{
    if (stream_index < hsessions.size())
        return hsessions[stream_index];
    else
        return nullptr;
}
