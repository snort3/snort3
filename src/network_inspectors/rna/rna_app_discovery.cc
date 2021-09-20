//--------------------------------------------------------------------------
// Copyright (C) 2020-2021 Cisco and/or its affiliates. All rights reserved.
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

// rna_app_discovery.cc authors: Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_app_discovery.h"

#include "detection/detection_engine.h"
#include "network_inspectors/appid/appid_session_api.h"

#include "rna_flow.h"
#include "rna_logger_common.h"

using namespace snort;

static THREAD_LOCAL uint8_t mac_addr[MAC_SIZE];

RnaTracker RnaAppDiscovery::get_server_rna_tracker(const Packet* p, RNAFlow* rna_flow)
{
    return rna_flow->get_server(p->flow->server_ip);
}

RnaTracker RnaAppDiscovery::get_client_rna_tracker(const Packet* p, RNAFlow* rna_flow)
{
    return rna_flow->get_client(p->flow->client_ip);
}

void RnaAppDiscovery::process(AppidEvent* appid_event, DiscoveryFilter& filter, RnaConfig* conf,
    RnaLogger& logger)
{
    const Packet* p = DetectionEngine::get_current_packet();

    // Published appid events may be on rebuilt packets
    if ( !p->flow )
        return;

    IpProtocol proto;
    if ( p->flow->pkt_type == PktType::TCP )
        proto = IpProtocol::TCP;
    else if ( p->flow->pkt_type == PktType::UDP )
        proto = IpProtocol::UDP;
    else
        return;

    RNAFlow* rna_flow = (RNAFlow*) p->flow->get_flow_data(RNAFlow::inspector_id);
    if ( !rna_flow )
        return;

    const auto& appid_change_bits = appid_event->get_change_bitset();
    const auto& appid_session_api = appid_event->get_appid_session_api();
    AppId service = appid_session_api.get_service_app_id();
    bool newservice = false;
    bool is_client = false;
    uint16_t port = p->flow->server_port;

    if ( appid_change_bits[APPID_SERVICE_BIT] or appid_change_bits[APPID_CLIENT_BIT] or
        appid_change_bits[APPID_PAYLOAD_BIT] )
    {
        AppId client, payload;
        appid_session_api.get_app_id(nullptr, &client, &payload, nullptr, nullptr);

        if ( appid_change_bits[APPID_SERVICE_BIT] and service > APP_ID_NONE )
        {
            if ( service == APP_ID_DHCP )
            {
                const SfIp& service_ip = appid_session_api.get_service_ip();
                if ( p->flow->client_ip.fast_eq6(service_ip) )
                    is_client = true;
                port = appid_session_api.get_service_port();
            }
            newservice = discover_service(p, filter, rna_flow, proto, conf, logger,
                port, service, is_client);
        }

        if ( appid_change_bits[APPID_CLIENT_BIT] and client > APP_ID_NONE
            and service > APP_ID_NONE )
        {
            const char* version = appid_session_api.get_client_info();
            discover_client(p, filter, rna_flow, conf, logger, version, client, service);
        }

        if ( appid_change_bits[APPID_PAYLOAD_BIT] and payload > APP_ID_NONE
             and service > APP_ID_NONE )
        {
            discover_payload(p, filter, rna_flow, proto, conf, logger, service, payload, client);
        }
    }

    if ( appid_change_bits[APPID_SERVICE_INFO_BIT] )
    {
        const char* vendor;
        const char* version;
        const AppIdServiceSubtype* subtype;
        appid_session_api.get_service_info(vendor, version, subtype);
        update_service_info(p, filter, rna_flow, proto, port, vendor, version, logger, conf,
            service, is_client);
    }
    else if ( newservice and appid_change_bits[APPID_SERVICE_BIT]
        and service > APP_ID_NONE )
    {
        update_service_info(p, filter, rna_flow, proto, port, nullptr, nullptr, logger, conf,
            service, is_client);
    }

    if ( conf->enable_banner_grab and p->is_from_server() and
        (appid_change_bits[APPID_RESPONSE_BIT] or
        appid_change_bits[APPID_SERVICE_INFO_BIT] or
        appid_change_bits[APPID_SERVICE_BIT]) )
    {
        discover_banner(p, filter, rna_flow, proto, logger, service);
    }

    // Appid supports login success/failure events, but not logoff event.
    if ( appid_change_bits[APPID_USER_INFO_BIT] and filter.is_user_monitored(p) )
    {
        bool login_success;
        const char* username = appid_session_api.get_user_info(service, login_success);
        if ( service > APP_ID_NONE and username and *username )
            discover_user(p, filter, rna_flow, logger, username, service, proto, conf,
                login_success);
    }
    if ( p->is_from_client() and ( appid_change_bits[APPID_HOST_BIT] or
        appid_change_bits[APPID_USERAGENT_BIT] ) )
    {
        auto processor = get_ua_fp_processor();
        if ( processor and processor->has_pattern() )
        {
            const AppIdHttpSession* hsession;

            if ( appid_event->get_is_http2() )
                hsession = appid_session_api.get_http_session(
                    appid_event->get_http2_stream_index());
            else
                hsession = appid_session_api.get_http_session();

            if ( hsession )
            {
                const char* host = hsession->get_cfield(REQ_HOST_FID);
                const char* uagent = hsession->get_cfield(REQ_AGENT_FID);
                analyze_user_agent_fingerprint(p, filter, rna_flow, host, uagent, logger,
                    *processor);
            }
        }
    }

    if ( appid_change_bits[APPID_NETBIOS_NAME_BIT] )
    {
        const char* netbios_name = appid_session_api.get_netbios_name();
        discover_netbios_name(p, filter, rna_flow, logger, netbios_name);
    }
}

bool RnaAppDiscovery::discover_service(const Packet* p, DiscoveryFilter& filter, RNAFlow* rna_flow,
    IpProtocol proto, RnaConfig* conf, RnaLogger& logger, uint16_t port, AppId service,
    bool is_client)
{
    RnaTracker htp;
    SfIp ip = p->flow->server_ip;

    if ( !is_client )
    {
        if ( !filter.is_host_monitored(p, nullptr, nullptr, FlowCheckDirection::DF_SERVER) )
            return false;
        htp = get_server_rna_tracker(p, rna_flow);
    }
    else
    {
        if ( !filter.is_host_monitored(p, nullptr, nullptr, FlowCheckDirection::DF_CLIENT) )
            return false;
        ip = p->flow->client_ip;
        htp = get_client_rna_tracker(p, rna_flow);
    }

    if ( !htp or !htp->is_visible() )
        return false;

    htp->update_last_seen();

    if ( conf and conf->max_host_services and conf->max_host_services <= htp->get_service_count() )
        return false;

    bool is_new = false;

    // Work on a local copy instead of reference as we release lock during event generations
    auto ha = htp->add_service(port, proto, (uint32_t) packet_time(), is_new, service);
    if ( is_new )
    {
        if ( proto == IpProtocol::TCP )
            logger.log(RNA_EVENT_NEW, NEW_TCP_SERVICE, p, &htp,
                (const struct in6_addr*) ip.get_ip6_ptr(), htp->get_last_seen_mac(mac_addr), &ha);
        else
            logger.log(RNA_EVENT_NEW, NEW_UDP_SERVICE, p, &htp,
                (const struct in6_addr*) ip.get_ip6_ptr(), htp->get_last_seen_mac(mac_addr), &ha);

        ha.hits = 0; // hit count is reset after logs are written
        htp->update_service(ha);
    }
    return is_new;
}

void RnaAppDiscovery::discover_payload(const Packet* p, DiscoveryFilter& filter, RNAFlow* rna_flow,
    IpProtocol proto, RnaConfig* conf, RnaLogger& logger, AppId service, AppId payload,
    AppId client)
{
    uint16_t lookup_port;
    size_t max_payloads = 0;
    RnaTracker srt = get_server_rna_tracker(p, rna_flow);

    if ( p->is_from_client() )
        lookup_port = p->flow->client_port;
    else
        lookup_port = p->flow->server_port;

    if ( !srt or !srt->is_visible() )
        return;

    srt->update_last_seen();
    if ( conf and conf->max_payloads )
        max_payloads = conf->max_payloads;

    // Add server payload
    if ( p->is_from_server() )
    {
        if ( !filter.is_host_monitored(p, nullptr, nullptr, FlowCheckDirection::DF_SERVER) )
            return;

        HostApplication local_ha;
        bool new_pld = srt->add_payload(local_ha, lookup_port, proto, payload, service,
            max_payloads);

        if ( new_pld )
        {
            if ( proto == IpProtocol::TCP )
                logger.log(RNA_EVENT_CHANGE, CHANGE_TCP_SERVICE_INFO, p, &srt,
                    (const struct in6_addr*) p->flow->server_ip.get_ip6_ptr(),
                    srt->get_last_seen_mac(mac_addr), &local_ha);
            else
                logger.log(RNA_EVENT_CHANGE, CHANGE_UDP_SERVICE_INFO, p, &srt,
                    (const struct in6_addr*) p->flow->server_ip.get_ip6_ptr(),
                    srt->get_last_seen_mac(mac_addr), &local_ha);
        }
    }

    // Add client payloads
    if ( !filter.is_host_monitored(p, nullptr, nullptr, FlowCheckDirection::DF_CLIENT) )
        return;

    RnaTracker crt = get_client_rna_tracker(p, rna_flow);
    if ( !crt or !crt->is_visible() )
        return;

    crt->update_last_seen();

    bool new_client_payload = false;
    HostClient hc(client, nullptr, service);
    new_client_payload = crt->add_client_payload(hc, payload, max_payloads);

    if ( new_client_payload )
        logger.log(RNA_EVENT_CHANGE, CHANGE_CLIENT_APP_UPDATE, p, &crt,
            (const struct in6_addr*) p->flow->client_ip.get_ip6_ptr(),
            crt->get_last_seen_mac(mac_addr), &hc);
}

void RnaAppDiscovery::update_service_info(const Packet* p, DiscoveryFilter& filter,
    RNAFlow* rna_flow, IpProtocol proto, uint16_t port, const char* vendor,
    const char* version, RnaLogger& logger, RnaConfig* conf, AppId service, bool is_client)
{
    RnaTracker htp;
    SfIp ip = p->flow->server_ip;
    if ( !is_client )
    {
        if ( !filter.is_host_monitored(p, nullptr, nullptr, FlowCheckDirection::DF_SERVER) )
            return;
        htp = get_server_rna_tracker(p, rna_flow);
    }
    else
    {
        if ( !filter.is_host_monitored(p, nullptr, nullptr, FlowCheckDirection::DF_CLIENT) )
            return;
        ip = p->flow->client_ip;
        htp = get_client_rna_tracker(p, rna_flow);
    }

    if ( !htp or !htp->is_visible() )
        return;

    htp->update_last_seen();

    HostApplication ha(port, proto, service, false);
    if ( !htp->update_service_info(ha, vendor, version, conf->max_host_service_info) )
        return;

    // Work on a local copy for eventing purpose
    ha.last_seen = (uint32_t) packet_time();

    if ( proto == IpProtocol::TCP )
        logger.log(RNA_EVENT_CHANGE, CHANGE_TCP_SERVICE_INFO, p, &htp,
            (const struct in6_addr*) ip.get_ip6_ptr(), htp->get_last_seen_mac(mac_addr), &ha);
    else
        logger.log(RNA_EVENT_CHANGE, CHANGE_UDP_SERVICE_INFO, p, &htp,
            (const struct in6_addr*) ip.get_ip6_ptr(), htp->get_last_seen_mac(mac_addr), &ha);

    ha.hits = 0;
    htp->update_service(ha);
}

void RnaAppDiscovery::discover_banner(const Packet* p, DiscoveryFilter& filter, RNAFlow* rna_flow,
    IpProtocol proto, RnaLogger& logger, AppId service)
{
    if ( !filter.is_host_monitored(p, nullptr, nullptr, FlowCheckDirection::DF_SERVER) )
        return;

    RnaTracker rt = get_server_rna_tracker(p, rna_flow);
    if ( !rt or !rt->is_visible() )
        return;
    rt->update_last_seen();

    if ( !rt->update_service_banner(p->flow->server_port, proto) )
        return;

    HostApplication ha(p->flow->server_port, proto, service, false);
    ha.last_seen = (uint32_t) packet_time();
    logger.log(RNA_EVENT_CHANGE, CHANGE_BANNER_UPDATE, p, &rt,
        (const struct in6_addr*) p->flow->server_ip.get_ip6_ptr(),
        rt->get_last_seen_mac(mac_addr), &ha);
}

void RnaAppDiscovery::discover_client(const Packet* p, DiscoveryFilter& filter, RNAFlow* rna_flow,
    RnaConfig* conf, RnaLogger& logger, const char* version, AppId client, AppId service)
{
    if ( !filter.is_host_monitored(p, nullptr, nullptr, FlowCheckDirection::DF_CLIENT) )
        return;

    RnaTracker rt = get_client_rna_tracker(p, rna_flow);
    if ( !rt or !rt->is_visible() )
        return;
    rt->update_last_seen();

    const uint8_t* mac;
    if ( layer::get_eth_layer(p) )
    {
        if ( p->is_from_server() )
            mac = layer::get_eth_layer(p)->ether_dst;
        else
            mac = layer::get_eth_layer(p)->ether_src;
    }
    else
    {
        RnaTracker crt = get_client_rna_tracker(p, rna_flow);
        if ( !crt or !crt->is_visible() )
            return;
        mac = crt->get_last_seen_mac(mac_addr);
    }

    if (conf and conf->max_host_client_apps and
        conf->max_host_client_apps <= rt->get_client_count())
        return;

    bool is_new = false;
    auto hc = rt->find_or_add_client(client, version, service, is_new);
    if ( is_new )
        logger.log(RNA_EVENT_NEW, NEW_CLIENT_APP, p, &rt,
            (const struct in6_addr*) p->flow->client_ip.get_ip6_ptr(), mac, &hc);
}

void RnaAppDiscovery::discover_user(const Packet* p, DiscoveryFilter& filter, RNAFlow* rna_flow,
    RnaLogger& logger, const char* username, AppId service, IpProtocol proto, RnaConfig* conf,
    bool login_success)
{
    assert(rna_flow);
    RnaTracker rt = rna_flow->get_tracker(p, filter);
    if ( !rt or !rt->is_visible() )
        return;

    if ( rt->update_service_user(p->flow->server_port, proto, username,
        (uint32_t) packet_time(), conf ? conf->max_host_services : 0, login_success) )
    {
        logger.log(RUA_EVENT, login_success ? CHANGE_USER_LOGIN : FAILED_USER_LOGIN,
            p, &rt, (const struct in6_addr*) p->ptrs.ip_api.get_dst()->get_ip6_ptr(),
            username, service, (uint32_t) packet_time());
    }
}

void RnaAppDiscovery::discover_netbios_name(const snort::Packet* p, DiscoveryFilter& filter,
    RNAFlow* rna_flow, RnaLogger& logger, const char* nb_name)
{
    RnaTracker rt = rna_flow->get_tracker(p, filter);
    if ( !rt or !rt->is_visible())
        return;

    if ( rt->set_netbios_name(nb_name) )
    {
        const auto& src_ip = p->ptrs.ip_api.get_src();
        const auto& src_ip_ptr = (const struct in6_addr*) src_ip->get_ip6_ptr();
        const auto& src_mac = layer::get_eth_layer(p)->ether_src;

        logger.log(RNA_EVENT_CHANGE, CHANGE_NETBIOS_NAME, src_ip_ptr, src_mac,
            &rt, p, (uint32_t) packet_time(), 0, nullptr, nullptr, nullptr, nullptr, nullptr,
            nullptr, APP_ID_NONE, nullptr, false, 0, 0, nullptr, nb_name);
    }
}

void RnaAppDiscovery::analyze_user_agent_fingerprint(const Packet* p, DiscoveryFilter& filter,
    RNAFlow* rna_flow, const char* host, const char* uagent, RnaLogger& logger,
    UaFpProcessor& processor)
{
    if ( !host or !uagent or
        !filter.is_host_monitored(p, nullptr, nullptr, FlowCheckDirection::DF_CLIENT))
        return;

    RnaTracker rt = get_client_rna_tracker(p, rna_flow);
    if ( !rt or !rt->is_visible() )
        return;
    rt->update_last_seen();

    const UaFingerprint* uafp = nullptr;
    const char* device_info = nullptr;
    bool jail_broken = false;
    processor.match_mpse(host, uagent, uafp, device_info, jail_broken);

    if ( uafp and rt->add_ua_fingerprint(uafp->fpid, uafp->fp_type, jail_broken,
        device_info, MAX_USER_AGENT_DEVICES) )
    {
        logger.log(RNA_EVENT_NEW, NEW_OS, p, &rt,
            (const struct in6_addr*)p->flow->client_ip.get_ip6_ptr(),
            rt->get_last_seen_mac(mac_addr), (FpFingerprint*)uafp, packet_time(),
            device_info, jail_broken);
    }
}
