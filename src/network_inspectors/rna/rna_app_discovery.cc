//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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

#include "rna_fingerprint_ua.h"
#include "rna_logger_common.h"

using namespace snort;

void RnaAppDiscovery::process(AppidEvent* appid_event, DiscoveryFilter& filter,
    RnaConfig* conf, RnaLogger& logger)
{
    const Packet* p = DetectionEngine::get_current_packet();

    // Published appid events may be on rebuilt packets
    if ( !p->flow or !filter.is_host_monitored(p) )
        return;

    IpProtocol proto;
    if ( p->flow->pkt_type == PktType::TCP )
        proto = IpProtocol::TCP;
    else if ( p->flow->pkt_type == PktType::UDP )
        proto = IpProtocol::UDP;
    else
        return;

    const auto& src_ip = p->ptrs.ip_api.get_src();
    auto ht = host_cache.find(*src_ip);
    if ( !ht )
        return; // should not happen as rna would get new flow event before appid event

    const uint8_t* src_mac;
    if ( layer::get_eth_layer(p) )
        src_mac = layer::get_eth_layer(p)->ether_src;
    else
        src_mac = ht->get_last_seen_mac();

    ht->update_last_seen();
    const auto& appid_change_bits = appid_event->get_change_bitset();
    const auto& appid_session_api = appid_event->get_appid_session_api();

    if ( appid_change_bits[APPID_SERVICE_BIT] or appid_change_bits[APPID_CLIENT_BIT] or
        appid_change_bits[APPID_PAYLOAD_BIT] )
    {
        AppId service, client, payload;
        appid_session_api.get_app_id(&service, &client, &payload, nullptr, nullptr);

        if ( appid_change_bits[APPID_SERVICE_BIT] and service > APP_ID_NONE )
        {
            if ( p->packet_flags & PKT_FROM_SERVER )
                discover_service(p, proto, ht, (const struct in6_addr*) src_ip->get_ip6_ptr(),
                    src_mac, conf, logger, p->flow->server_port, service);
            else if ( p->packet_flags & PKT_FROM_CLIENT )
                discover_service(p, proto, ht, (const struct in6_addr*) src_ip->get_ip6_ptr(),
                    src_mac, conf, logger, p->flow->client_port, service);
        }

        if (appid_change_bits[APPID_CLIENT_BIT] and client > APP_ID_NONE
            and service > APP_ID_NONE )
        {
            const char* version = appid_session_api.get_client_version();
            discover_client(p, ht, (const struct in6_addr*) src_ip->get_ip6_ptr(), src_mac,
                conf, logger, version, client, service);
        }
    }

    if ( appid_change_bits[APPID_SERVICE_VENDOR_BIT] or appid_change_bits[APPID_VERSION_BIT] )
    {
        const char* vendor;
        const char* version;
        const AppIdServiceSubtype* subtype;
        AppId service, client, payload;

        appid_session_api.get_app_id(&service, &client, &payload, nullptr, nullptr);
        appid_session_api.get_service_info(vendor, version, subtype);
        update_service_info(p, proto, vendor, version, ht, src_ip, src_mac, logger, conf,
            service);
    }

    if ( p->is_from_client() and ( appid_change_bits[APPID_HOST_BIT] or
        appid_change_bits[APPID_USERAGENT_BIT] ) )
    {
        const AppIdHttpSession* hsession;

        if ( appid_event->get_is_http2() )
            hsession = appid_session_api.get_http_session(appid_event->get_http2_stream_index());
        else
            hsession = appid_session_api.get_http_session();

        if ( hsession )
        {
            const char* host = hsession->get_cfield(REQ_HOST_FID);
            const char* uagent = hsession->get_cfield(REQ_AGENT_FID);
            analyze_user_agent_fingerprint(p, host, uagent, ht, src_ip, src_mac, logger);
        }
    }
}

void RnaAppDiscovery::discover_service(const Packet* p, IpProtocol proto, RnaTracker& rt,
    const struct in6_addr* src_ip, const uint8_t* src_mac, RnaConfig* conf,
    RnaLogger& logger, uint16_t port, AppId service)
{
    if ( conf and conf->max_host_services and conf->max_host_services <= rt->get_service_count() )
        return;

    bool is_new = false;

    // Work on a local copy instead of reference as we release lock during event generations
    auto ha = rt->get_service(port, proto, (uint32_t) packet_time(), is_new, service);
    if ( is_new )
    {
        if ( proto == IpProtocol::TCP )
            logger.log(RNA_EVENT_NEW, NEW_TCP_SERVICE, p, &rt, src_ip, src_mac, &ha);
        else
            logger.log(RNA_EVENT_NEW, NEW_UDP_SERVICE, p, &rt, src_ip, src_mac, &ha);

        ha.hits = 0; // hit count is reset after logs are written
        rt->update_service(ha);
    }
}

void RnaAppDiscovery::update_service_info(const Packet* p, IpProtocol proto, const char* vendor,
    const char* version, RnaTracker& rt, const SfIp* ip, const uint8_t* src_mac, RnaLogger& logger,
    RnaConfig* conf, AppId service)
{
    if ( !vendor and !version )
        return;

    HostApplication ha(p->flow->server_port, proto, service, false);
    if ( !rt->update_service_info(ha, vendor, version, conf->max_host_service_info) )
        return;

    // Work on a local copy for eventing purpose
    ha.last_seen = (uint32_t) packet_time();

    if ( proto == IpProtocol::TCP )
        logger.log(RNA_EVENT_CHANGE, CHANGE_TCP_SERVICE_INFO, p, &rt,
            (const struct in6_addr*) ip->get_ip6_ptr(), src_mac, &ha);
    else
        logger.log(RNA_EVENT_CHANGE, CHANGE_UDP_SERVICE_INFO, p, &rt,
            (const struct in6_addr*) ip->get_ip6_ptr(), src_mac, &ha);

    ha.hits = 0;
    rt->update_service(ha);
}

void RnaAppDiscovery::discover_client(const Packet* p, RnaTracker& rt,
    const struct in6_addr* src_ip, const uint8_t* src_mac, RnaConfig* conf,
    RnaLogger& logger, const char* version, AppId client, AppId service)
{
    if (conf and conf->max_host_client_apps and
        conf->max_host_client_apps <= rt->get_client_count())
        return;

    bool is_new = false;

    auto hc = rt->get_client(client, version, service, is_new);
    if ( is_new )
    {
        logger.log(RNA_EVENT_NEW, NEW_CLIENT_APP, p, &rt, src_ip, src_mac, &hc);
    }
}

void RnaAppDiscovery::analyze_user_agent_fingerprint(const Packet* p, const char* host,
    const char* uagent, RnaTracker& rt, const SfIp* ip, const uint8_t* src_mac, RnaLogger& logger)
{
    if ( !host or !uagent )
        return;

    const auto& processor = get_ua_fp_processor();
    if ( !processor )
        return;

    const UaFingerprint* uafp = nullptr;
    const char* device_info = nullptr;
    bool jail_broken = false;
    processor->match_mpse(host, uagent, uafp, device_info, jail_broken);

    if ( uafp and rt->add_ua_fingerprint(uafp->fpid, uafp->fp_type, jail_broken,
        device_info, MAX_USER_AGENT_DEVICES) )
    {
        logger.log(RNA_EVENT_NEW, NEW_OS, p, &rt, (const struct in6_addr*)ip->get_ip6_ptr(),
            src_mac, (FpFingerprint*)uafp, packet_time());
    }
}

