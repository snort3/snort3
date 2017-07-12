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

// appid_discovery.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_discovery.h"

#include "appid_config.h"
#include "appid_detector.h"
#include "app_forecast.h"
#include "appid_http_session.h"
#include "app_info_table.h"
#include "appid_inspector.h"
#include "appid_module.h"
#include "appid_session.h"
#include "appid_utils/ip_funcs.h"
#include "appid_utils/network_set.h"
#include "host_port_app_cache.h"
#include "thirdparty_appid_utils.h"
#include "service_plugins/service_discovery.h"
#include "client_plugins/client_discovery.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/http_url_patterns.h"

#include "profiler/profiler.h"
#include "log/messages.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

AppIdDiscovery::AppIdDiscovery()
{
    tcp_patterns = new SearchTool;
    udp_patterns = new SearchTool;
}

AppIdDiscovery::~AppIdDiscovery()
{
    AppIdPatternMatchNode* pd = pattern_data_list;
    while (pd)
    {
        pattern_data_list = pd->next;
        snort_free(pd);
        pd = pattern_data_list;
    }

    delete tcp_patterns;
    delete udp_patterns;

    for ( auto kv : tcp_detectors )
        delete kv.second;

    for ( auto kv : udp_detectors )
        delete kv.second;
}

void AppIdDiscovery::initialize_plugins()
{
    ServiceDiscovery::get_instance();
    ClientDiscovery::get_instance();
}

void AppIdDiscovery::finalize_plugins()
{
    ServiceDiscovery::get_instance().finalize_service_patterns();
    ClientDiscovery::get_instance().finalize_client_plugins();
}

void AppIdDiscovery::release_plugins()
{
    delete &ServiceDiscovery::get_instance();
    delete &ClientDiscovery::get_instance();
}

void AppIdDiscovery::register_detector(std::string name, AppIdDetector* cd,  IpProtocol proto)
{
    // FIXIT-L - check for dup name?
    if ( proto == IpProtocol::TCP )
        tcp_detectors[ name ] = cd;
    else if ( proto == IpProtocol::UDP )
        udp_detectors[ name ] = cd;
    else
        ErrorMessage("Detector %s has unsupported protocol %u", name.c_str(), (unsigned)proto);
}

void AppIdDiscovery::add_pattern_data(AppIdDetector* detector, SearchTool* st, int position, const
    uint8_t* const pattern, unsigned size, unsigned nocase, int* count)
{
    AppIdPatternMatchNode* pd = (AppIdPatternMatchNode*)snort_calloc(
        sizeof(AppIdPatternMatchNode));
    pd->service = detector;
    pd->pattern_start_pos = position;
    pd->size = size;
    (*count)++;
    pd->next = pattern_data_list;
    pattern_data_list = pd;
    st->add((const char*)pattern, size, pd, nocase);
}

void AppIdDiscovery::register_tcp_pattern(AppIdDetector* detector, const uint8_t* const pattern,
    unsigned size, int position, unsigned nocase)
{
    int* count = &tcp_pattern_count;
    add_pattern_data(detector, tcp_patterns, position, pattern, size, nocase, count);
}

void AppIdDiscovery::register_udp_pattern(AppIdDetector* detector, const uint8_t* const pattern,
    unsigned size, int position, unsigned nocase)
{
    int* count = &udp_pattern_count;
    add_pattern_data(detector, udp_patterns, position, pattern, size, nocase, count);
}

int AppIdDiscovery::add_service_port(AppIdDetector*, const ServiceDetectorPort&)
{
    return APPID_EINVALID;
}

static inline int PENetworkMatch(const SfIp* pktAddr, const PortExclusion* pe)
{
    const uint32_t* pkt = pktAddr->get_ip6_ptr();
    const uint32_t* nm = pe->netmask.u6_addr32;
    const uint32_t* peIP = pe->ip.u6_addr32;
    return (((pkt[0] & nm[0]) == peIP[0])
           && ((pkt[1] & nm[1]) == peIP[1])
           && ((pkt[2] & nm[2]) == peIP[2])
           && ((pkt[3] & nm[3]) == peIP[3]));
}

static inline int check_port_exclusion(const Packet* pkt, bool reversed)
{
    AppIdPortExclusions* src_port_exclusions;
    AppIdPortExclusions* dst_port_exclusions;
    SF_LIST* pe_list;
    PortExclusion* pe;
    const SfIp* s_ip;
    AppIdConfig* config = AppIdInspector::get_inspector()->get_appid_config();

    if ( pkt->is_tcp() )
    {
        src_port_exclusions = &config->tcp_port_exclusions_src;
        dst_port_exclusions = &config->tcp_port_exclusions_dst;
    }
    else if ( pkt->is_udp() )
    {
        src_port_exclusions = &config->udp_port_exclusions_src;
        dst_port_exclusions = &config->udp_port_exclusions_dst;
    }
    else
        return 0;

    /* check the source port */
    uint16_t port = reversed ? pkt->ptrs.dp : pkt->ptrs.sp;
    if ( port && (pe_list = (*src_port_exclusions)[port]) != nullptr )
    {
        s_ip = reversed ? pkt->ptrs.ip_api.get_dst() : pkt->ptrs.ip_api.get_src();

        SF_LNODE* node;

        /* walk through the list of port exclusions for this port */
        for ( pe = (PortExclusion*)sflist_first(pe_list, &node);
            pe;
            pe = (PortExclusion*)sflist_next(&node) )
        {
            if ( PENetworkMatch(s_ip, pe))
                return 1;
        }
    }

    /* check the dest port */
    port = reversed ? pkt->ptrs.sp : pkt->ptrs.dp;
    if ( port && (pe_list = (*dst_port_exclusions)[port]) != nullptr )
    {
        s_ip = reversed ? pkt->ptrs.ip_api.get_src() : pkt->ptrs.ip_api.get_dst();

        SF_LNODE* node;
        /* walk through the list of port exclusions for this port */
        for ( pe = (PortExclusion*)sflist_first(pe_list, &node);
            pe;
            pe = (PortExclusion*)sflist_next(&node) )
        {
            if ( PENetworkMatch(s_ip, pe))
                return 1;
        }
    }

    return 0;
}

static inline unsigned get_ipfuncs_flags(const Packet* p, bool dst)
{
    const SfIp* sf_ip;
    unsigned flags;
    int32_t zone;
#ifdef USE_RNA_CONFIG
    NSIPv6Addr ip6;
    NetworkSet* net_list;
    AppIdConfig* config = AppIdConfig::get_appid_config();
#endif

    if (!dst)
    {
        zone = p->pkth->ingress_group;
        sf_ip = p->ptrs.ip_api.get_src();
    }
    else
    {
        zone = (p->pkth->egress_index == DAQ_PKTHDR_UNKNOWN) ?
            p->pkth->ingress_group : p->pkth->egress_group;
        if (zone == DAQ_PKTHDR_FLOOD)
            return 0;
        sf_ip = p->ptrs.ip_api.get_dst();
    }

#ifdef USE_RNA_CONFIG
    if (zone >= 0 && zone < MAX_ZONES && config->net_list_by_zone[zone])
        net_list = config->net_list_by_zone[zone];
    else
        net_list = config->net_list;

    if ( sf_ip->is_ip4() )
    {
        if (sf_ip->get_ip4_value() == 0xFFFFFFFF)
            return IPFUNCS_CHECKED;
        NetworkSetManager::contains_ex(net_list, ntohl(sf_ip->get_ip4_value()), &flags);
    }
    else
    {
        memcpy(&ip6, sf_ip->get_ip6_ptr(), sizeof(ip6));
        NetworkSetManager::ntoh_ipv6(&ip6);
        NetworkSetManager::contains6_ex(net_list, &ip6, &flags);
    }
#else
    UNUSED(zone);
    if (sf_ip->is_ip4() && sf_ip->get_ip4_value() == 0xFFFFFFFF)
        return IPFUNCS_CHECKED;
    // FIXIT-M Defaulting to checking everything everywhere until RNA config is reimplemented
    flags = IPFUNCS_HOSTS_IP | IPFUNCS_USER_IP | IPFUNCS_APPLICATION;
#endif

    return flags | IPFUNCS_CHECKED;
}

static inline bool is_special_session_monitored(const Packet* p)
{
    if ( p->is_ip4() )
    {
        if (p->is_udp() && ((p->ptrs.sp == 68 && p->ptrs.dp == 67)
            || (p->ptrs.sp == 67 &&  p->ptrs.dp == 68)))
        {
            return true;
        }
    }
    return false;
}

static bool set_network_attributes(AppIdSession* asd, Packet* p, IpProtocol& protocol,
    int& direction)
{
    if (asd)
    {
        if (asd->common.flow_type == APPID_FLOW_TYPE_IGNORE)
            return false;

        if (asd->common.flow_type == APPID_FLOW_TYPE_NORMAL)
        {
            protocol = asd->protocol;
            asd->flow = p->flow;
        }
        else if (p->is_tcp())
            protocol = IpProtocol::TCP;
        else
            protocol = IpProtocol::UDP;

        const SfIp* ip = p->ptrs.ip_api.get_src();
        if (asd->common.initiator_port)
            direction = (asd->common.initiator_port == p->ptrs.sp) ?
                APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
        else
            direction = ip->fast_equals_raw(asd->common.initiator_ip) ?
                APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;

        asd->in_expected_cache = false;
    }
    else
    {
        if (p->is_tcp())
            protocol = IpProtocol::TCP;
        else if (p->is_udp())
            protocol = IpProtocol::UDP;
        else if ( p->is_ip4() || p->is_ip6() )
            protocol = p->get_ip_proto_next();
        else
            return false;

        // FIXIT-L Refactor to use direction symbols defined by snort proper
        direction = p->is_from_client() ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    }

    return true;
}

static bool is_packet_ignored(AppIdSession* asd, Packet* p, int& direction)
{
// FIXIT-M - Need to convert this _dpd stream api call to the correct snort++ method
#ifdef REMOVED_WHILE_NOT_IN_USE
    bool is_http2     = false; // _dpd.streamAPI->is_session_http2(p->flow);
#else
    bool is_http2     = false;
#endif
    if (is_http2)
    {
        if (asd)
            asd->is_http2 = true;
        if ( !p->is_rebuilt() )
        {
            // For HTTP/2, only examine packets that have been rebuilt as HTTP/1 packets.
            appid_stats.ignored_packets++;
            return true;
        }
    }
    else if ( p->is_rebuilt() && !p->flow->is_proxied() )
    {
        if ( direction == APP_ID_FROM_INITIATOR &&
            asd && asd->hsession && asd->hsession->get_offsets_from_rebuilt )
        {
            HttpPatternMatchers::get_instance()->get_http_offsets(p, asd->hsession);
            if (asd->session_logging_enabled)
                LogMessage(
                    "AppIdDbg %s offsets from rebuilt packet: uri: %u-%u cookie: %u-%u\n",
                    asd->session_logging_id,
                    asd->hsession->fieldOffset[REQ_URI_FID],
                    asd->hsession->fieldEndOffset[REQ_URI_FID],
                    asd->hsession->fieldOffset[REQ_COOKIE_FID],
                    asd->hsession->fieldEndOffset[REQ_COOKIE_FID]);
        }
        appid_stats.ignored_packets++;
        return true;
    }

    return false;
}

static uint64_t is_session_monitored(AppIdSession& asd, const Packet* p, int dir)
{
    uint64_t flags = 0;
    uint64_t flow_flags = APPID_SESSION_DISCOVER_APP;

    flow_flags |= (dir == APP_ID_FROM_INITIATOR) ?
        APPID_SESSION_INITIATOR_SEEN : APPID_SESSION_RESPONDER_SEEN;

    flow_flags |= asd.common.flags;
    // FIXIT-M - the 2.x purpose of this check is stop monitoring a flow after a
    //           reload if the flow ip addresses are no longer configured to be
    //           monitored... this may not apply in snort++, find out and fix
    //           accordingly
    if ( asd.common.policyId != asd.config->appIdPolicyId )
    {
        if (check_port_exclusion(p, dir == APP_ID_FROM_RESPONDER))
        {
            flow_flags |= APPID_SESSION_INITIATOR_SEEN | APPID_SESSION_RESPONDER_SEEN |
                APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_RESPONDER_CHECKED;
            flow_flags &= ~(APPID_SESSION_INITIATOR_MONITORED |
                APPID_SESSION_RESPONDER_MONITORED);
            return flow_flags;
        }
        if (dir == APP_ID_FROM_INITIATOR)
        {
            if (asd.get_session_flags(APPID_SESSION_INITIATOR_CHECKED))
            {
                flags = get_ipfuncs_flags(p, false);
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                else
                    flow_flags &= ~APPID_SESSION_INITIATOR_MONITORED;
            }

            if (asd.get_session_flags(APPID_SESSION_RESPONDER_CHECKED))
            {
                flags = get_ipfuncs_flags(p, true);
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                else
                    flow_flags &= ~APPID_SESSION_RESPONDER_MONITORED;
            }
        }
        else
        {
            if (asd.get_session_flags(APPID_SESSION_RESPONDER_CHECKED))
            {
                flags = get_ipfuncs_flags(p, false);
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
                else
                    flow_flags &= ~APPID_SESSION_RESPONDER_MONITORED;
            }

            if (asd.get_session_flags(APPID_SESSION_INITIATOR_CHECKED))
            {
                flags = get_ipfuncs_flags(p, true);
                if (flags & IPFUNCS_HOSTS_IP)
                    flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
                else
                    flow_flags &= ~APPID_SESSION_INITIATOR_MONITORED;
            }
        }
    }

    if (asd.get_session_flags(APPID_SESSION_BIDIRECTIONAL_CHECKED) ==
        APPID_SESSION_BIDIRECTIONAL_CHECKED)
        return flow_flags;

    if (dir == APP_ID_FROM_INITIATOR)
    {
        if (!asd.get_session_flags(APPID_SESSION_INITIATOR_CHECKED))
        {
            flags = get_ipfuncs_flags(p, false);
            flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
            if (flags & IPFUNCS_HOSTS_IP)
                flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
            if (flags & IPFUNCS_USER_IP)
                flow_flags |= APPID_SESSION_DISCOVER_USER;
            if (flags & IPFUNCS_APPLICATION)
                flow_flags |= APPID_SESSION_DISCOVER_APP;
            if (is_special_session_monitored(p))
                flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
        }

        if (!(flow_flags & APPID_SESSION_DISCOVER_APP)
            && !asd.get_session_flags(APPID_SESSION_RESPONDER_CHECKED))
        {
            flags = get_ipfuncs_flags(p, true);
            if (flags & IPFUNCS_CHECKED)
                flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
            if (flags & IPFUNCS_HOSTS_IP)
                flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
            if (flags & IPFUNCS_APPLICATION)
                flow_flags |= APPID_SESSION_DISCOVER_APP;
            if (is_special_session_monitored(p))
                flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
        }
    }
    else
    {
        if (!asd.get_session_flags(APPID_SESSION_RESPONDER_CHECKED))
        {
            flags = get_ipfuncs_flags(p, false);
            flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
            if (flags & IPFUNCS_HOSTS_IP)
                flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
            if (flags & IPFUNCS_APPLICATION)
                flow_flags |= APPID_SESSION_DISCOVER_APP;
            if (is_special_session_monitored(p))
                flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
        }

        if (!(flow_flags & APPID_SESSION_DISCOVER_APP)
            && !asd.get_session_flags(APPID_SESSION_INITIATOR_CHECKED))
        {
            flags = get_ipfuncs_flags(p, true);
            if (flags & IPFUNCS_CHECKED)
                flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
            if (flags & IPFUNCS_HOSTS_IP)
                flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
            if (flags & IPFUNCS_USER_IP)
                flow_flags |= APPID_SESSION_DISCOVER_USER;
            if (flags & IPFUNCS_APPLICATION)
                flow_flags |= APPID_SESSION_DISCOVER_APP;
            if (is_special_session_monitored(p))
                flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
        }
    }

    return flow_flags;
}

static uint64_t is_session_monitored(const Packet* p, int dir)
{
    uint64_t flags = 0;
    uint64_t flow_flags = APPID_SESSION_DISCOVER_APP;

    flow_flags |= (dir == APP_ID_FROM_INITIATOR) ?
        APPID_SESSION_INITIATOR_SEEN : APPID_SESSION_RESPONDER_SEEN;

    if (check_port_exclusion(p, false))
    {
        flow_flags |= APPID_SESSION_INITIATOR_SEEN | APPID_SESSION_RESPONDER_SEEN |
            APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_RESPONDER_CHECKED;
    }
    else if (dir == APP_ID_FROM_INITIATOR)
    {
        flags = get_ipfuncs_flags(p, false);
        flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
        if (flags & IPFUNCS_HOSTS_IP)
            flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
        if (flags & IPFUNCS_USER_IP)
            flow_flags |= APPID_SESSION_DISCOVER_USER;
        if (flags & IPFUNCS_APPLICATION)
            flow_flags |= APPID_SESSION_DISCOVER_APP;
        if (!(flow_flags & APPID_SESSION_DISCOVER_APP))
        {
            flags = get_ipfuncs_flags(p, true);
            if (flags & IPFUNCS_CHECKED)
                flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
            if (flags & IPFUNCS_HOSTS_IP)
                flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
            if (flags & IPFUNCS_APPLICATION)
                flow_flags |= APPID_SESSION_DISCOVER_APP;
        }
        if (is_special_session_monitored(p))
            flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
    }
    else
    {
        flags = get_ipfuncs_flags(p, false);
        flow_flags |= APPID_SESSION_RESPONDER_CHECKED;
        if (flags & IPFUNCS_HOSTS_IP)
            flow_flags |= APPID_SESSION_RESPONDER_MONITORED;
        if (flags & IPFUNCS_APPLICATION)
            flow_flags |= APPID_SESSION_DISCOVER_APP;
        if (!(flow_flags & APPID_SESSION_DISCOVER_APP))
        {
            flags = get_ipfuncs_flags(p, true);
            if (flags & IPFUNCS_CHECKED)
                flow_flags |= APPID_SESSION_INITIATOR_CHECKED;
            if (flags & IPFUNCS_HOSTS_IP)
                flow_flags |= APPID_SESSION_INITIATOR_MONITORED;
            if (flags & IPFUNCS_USER_IP)
                flow_flags |= APPID_SESSION_DISCOVER_USER;
            if (flags & IPFUNCS_APPLICATION)
                flow_flags |= APPID_SESSION_DISCOVER_APP;
        }

        if (is_special_session_monitored(p))
            flow_flags |= APPID_SESSION_SPECIAL_MONITORED;
    }

    return flow_flags;
}

static void lookup_appid_by_host_port(AppIdSession* asd, Packet* p, IpProtocol protocol,
    int direction)
{
    HostPortVal* hv = nullptr;
    uint16_t port = 0;
    const SfIp* ip = nullptr;
    asd->scan_flags |= SCAN_HOST_PORT_FLAG;
    if (direction == APP_ID_FROM_INITIATOR)
    {
        ip = p->ptrs.ip_api.get_dst();
        port = p->ptrs.dp;
    }
    else
    {
        ip = p->ptrs.ip_api.get_src();
        port = p->ptrs.sp;
    }
    if ((hv = HostPortCache::find(ip, port, protocol)))
    {
        switch (hv->type)
        {
        case 1:
            asd->client_app_id = hv->appId;
            asd->client_disco_state = APPID_DISCO_STATE_FINISHED;
            break;
        case 2:
            asd->payload_app_id = hv->appId;
            break;
        default:
            asd->service_app_id = hv->appId;
            asd->sync_with_snort_id(hv->appId, p);
            asd->service_disco_state = APPID_DISCO_STATE_FINISHED;
            asd->client_disco_state = APPID_DISCO_STATE_FINISHED;
            asd->set_session_flags(APPID_SESSION_SERVICE_DETECTED);
            if (thirdparty_appid_module)
                thirdparty_appid_module->session_delete(asd->tpsession, 1);

            asd->tpsession = nullptr;
        }
    }
}

void AppIdDiscovery::do_application_discovery(Packet* p)
{
    IpProtocol protocol = IpProtocol::PROTO_NOT_SET;
    bool isTpAppidDiscoveryDone = false;
    int direction = 0;

    AppIdSession* asd = (AppIdSession*)p->flow->get_flow_data(AppIdSession::inspector_id);
    if ( !set_network_attributes(asd, p, protocol, direction) )
        return;

    if ( is_packet_ignored(asd, p, direction) )
        return;

    uint64_t flow_flags;
    if (asd)
        flow_flags = is_session_monitored(*asd, p, direction);
    else
        flow_flags = is_session_monitored(p, direction);

    if ( !( flow_flags & (APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED) ) )
    {
        if ( !asd )
        {
            uint16_t port = 0;

            const SfIp* ip = (direction == APP_ID_FROM_INITIATOR) ?
                p->ptrs.ip_api.get_src() : p->ptrs.ip_api.get_dst();
            if ((protocol == IpProtocol::TCP || protocol == IpProtocol::UDP)
                && p->ptrs.sp != p->ptrs.dp)
            {
                port = (direction == APP_ID_FROM_INITIATOR) ? p->ptrs.sp : p->ptrs.dp;
            }

            AppIdSession* tmp_session = new AppIdSession(protocol, ip, port);

            if ((flow_flags & APPID_SESSION_BIDIRECTIONAL_CHECKED) ==
                APPID_SESSION_BIDIRECTIONAL_CHECKED)
                tmp_session->common.flow_type = APPID_FLOW_TYPE_IGNORE;
            else
                tmp_session->common.flow_type = APPID_FLOW_TYPE_TMP;
            tmp_session->common.flags = flow_flags;
            tmp_session->common.policyId =
                AppIdInspector::get_inspector()->get_appid_config()->appIdPolicyId;
            p->flow->set_flow_data(tmp_session);
        }
        else
        {
            asd->common.flags = flow_flags;
            if ( ( flow_flags & APPID_SESSION_BIDIRECTIONAL_CHECKED) ==
                APPID_SESSION_BIDIRECTIONAL_CHECKED )
                asd->common.flow_type = APPID_FLOW_TYPE_IGNORE;
            asd->common.policyId = asd->config->appIdPolicyId;
        }

        return;
    }

    if ( !asd || asd->common.flow_type == APPID_FLOW_TYPE_TMP )
    {
        asd = AppIdSession::allocate_session(p, protocol, direction);
        if (asd->session_logging_enabled)
            LogMessage("AppIdDbg %s new session\n", asd->session_logging_id);
    }

    // FIXIT-L - from this point on we always have a valid ptr to an AppIdSession and a Packet
    //           refactor to pass these as refs and delete any checks for null
    appid_stats.processed_packets++;
    asd->session_packet_count++;

    if (direction == APP_ID_FROM_INITIATOR)
        asd->stats.initiator_bytes += p->pkth->pktlen;
    else
        asd->stats.responder_bytes += p->pkth->pktlen;

    asd->common.flags = flow_flags;
    asd->common.policyId = asd->config->appIdPolicyId;

    if (asd->get_session_flags(APPID_SESSION_IGNORE_FLOW))
    {
        if ( asd->session_logging_enabled &&
            !asd->get_session_flags(APPID_SESSION_IGNORE_FLOW_LOGGED) )
        {
            asd->set_session_flags(APPID_SESSION_IGNORE_FLOW_LOGGED);
            LogMessage("AppIdDbg %s Ignoring connection with service %d\n",
                asd->session_logging_id, asd->service_app_id);
        }

        return;
    }

    if (p->packet_flags & PKT_STREAM_ORDER_BAD)
        asd->set_session_flags(APPID_SESSION_OOO);
    else if ( p->is_tcp() && p->ptrs.tcph )
    {
        const auto* tcph = p->ptrs.tcph;
        if ( tcph->is_rst() && asd->previous_tcp_flags == TH_SYN )
        {
            uint16_t port = 0;
            const SfIp* ip = nullptr;

            asd->set_session_flags(APPID_SESSION_SYN_RST);
            if (asd->service_ip.is_set())
            {
                ip = &asd->service_ip;
                port = asd->service_port;
            }
            else
            {
                ip = p->ptrs.ip_api.get_src();
                port = p->ptrs.sp;
            }

            AppIdServiceState::check_reset(asd, ip, port);
        }

        asd->previous_tcp_flags = p->ptrs.tcph->th_flags;
    }

    /*HostPort based AppId.  */
    if ( !(asd->scan_flags & SCAN_HOST_PORT_FLAG) )
        lookup_appid_by_host_port(asd, p, protocol, direction);

    asd->check_app_detection_restart();

#ifdef REMOVED_WHILE_NOT_IN_USE
    // do third party detector processing
    isTpAppidDiscoveryDone = do_third_party_discovery(asd, protocol, ip, p, direction);
#endif

    if ( !asd->get_session_flags(APPID_SESSION_PORT_SERVICE_DONE) )
    {
        switch (protocol)
        {
        case IpProtocol::TCP:
            if (asd->get_session_flags(APPID_SESSION_SYN_RST)) // TCP-specific exception
                break;
            // fallthrough
        case IpProtocol::UDP:
            // Both TCP and UDP need this test to be made
            //  against only the p->src_port of the response.
            // For all other cases the port parameter is never checked.
            if (direction != APP_ID_FROM_RESPONDER)
                break;
            // fallthrough
        // All protocols other than TCP and UDP come straight here.
        default:
        {
            asd->port_service_id = asd->config->get_port_service_id(protocol, p->ptrs.sp);
            if (asd->session_logging_enabled)
                LogMessage("AppIdDbg %s port service %d\n",
                    asd->session_logging_id, asd->port_service_id);
            asd->set_session_flags(APPID_SESSION_PORT_SERVICE_DONE);
        }
        break;
        }
    }

    /* Length-based detectors. */
    /* Only check if:
     *  - Port service didn't find anything (and we haven't yet either).
     *  - We haven't hit the max packets allowed for detector sequence matches.
     *  - Packet has data (we'll ignore 0-sized packets in sequencing). */
    if ( (asd->port_service_id <= APP_ID_NONE)
        && (asd->length_sequence.sequence_cnt < LENGTH_SEQUENCE_CNT_MAX)
        && (p->dsize > 0))
    {
        uint8_t index = asd->length_sequence.sequence_cnt;
        asd->length_sequence.proto = protocol;
        asd->length_sequence.sequence_cnt++;
        asd->length_sequence.sequence[index].direction = direction;
        asd->length_sequence.sequence[index].length    = p->dsize;
        asd->port_service_id = find_length_app_cache(&asd->length_sequence);
        if (asd->port_service_id > APP_ID_NONE)
            asd->set_session_flags(APPID_SESSION_PORT_SERVICE_DONE);
    }

    /* exceptions for rexec and any other service detector that needs to see SYN and SYN/ACK */
    if (asd->get_session_flags(APPID_SESSION_REXEC_STDERR))
    {
        ServiceDiscovery::get_instance().identify_service(asd, p, direction);
        if (asd->service_app_id == APP_ID_DNS &&
            asd->config->mod_config->dns_host_reporting &&
            asd->dsession && asd->dsession->host )
        {
            size_t size = asd->dsession->host_len;
            AppId client_app_id = APP_ID_NONE, payload_app_id = APP_ID_NONE;
            dns_host_scan_hostname((const uint8_t*)asd->dsession->host, size,
                &client_app_id, &payload_app_id);
            asd->set_client_app_id_data(client_app_id, nullptr);
        }
        else if (asd->service_app_id == APP_ID_RTMP)
            asd->examine_rtmp_metadata();
        else if (asd->get_session_flags(APPID_SESSION_SSL_SESSION) && asd->tsession)
            asd->examine_ssl_metadata(p);
    }
    // FIXIT-M - snort 2.x has added a check for midstream pickup to this if, do we need that?
    else if (protocol != IpProtocol::TCP || !p->dsize || (p->packet_flags & PKT_STREAM_ORDER_OK))
    {
        if (asd->service_disco_state != APPID_DISCO_STATE_FINISHED)
            isTpAppidDiscoveryDone =
                ServiceDiscovery::get_instance().do_service_discovery(*asd, p, direction);
        if (asd->client_disco_state != APPID_DISCO_STATE_FINISHED)
            isTpAppidDiscoveryDone =
                ClientDiscovery::get_instance().do_client_discovery(*asd, p, direction);
        asd->set_session_flags(APPID_SESSION_ADDITIONAL_PACKET);
    }
    else
    {
        if (asd->session_logging_enabled && p->dsize &&
            !asd->get_session_flags(APPID_SESSION_OOO_LOGGED))
        {
            asd->set_session_flags(APPID_SESSION_OOO_LOGGED);
            LogMessage("AppIdDbg %s packet out-of-order\n", asd->session_logging_id);
        }
    }

    AppId service_app_id = asd->pick_service_app_id();
    AppId payload_app_id = asd->pick_payload_app_id();

    if (service_app_id > APP_ID_NONE)
    {
        if (asd->get_session_flags(APPID_SESSION_DECRYPTED))
        {
            if (asd->misc_app_id == APP_ID_NONE)
                asd->update_encrypted_app_id(service_app_id);
        }
// FIXIT-M Need to determine what api to use for this _dpd function
#if 1
        UNUSED(isTpAppidDiscoveryDone);
#else
        else if (isTpAppidDiscoveryDone && isSslServiceAppId(service_app_id) &&
            _dpd.isSSLPolicyEnabled(nullptr))
            asd->set_session_flags(APPID_SESSION_CONTINUE);
#endif
    }

    asd->set_application_ids(service_app_id, asd->pick_client_app_id(), payload_app_id,
        asd->pick_misc_app_id());

    /* Set the field that the Firewall queries to see if we have a search engine. */
    if (asd->search_support_type == UNKNOWN_SEARCH_ENGINE && payload_app_id > APP_ID_NONE)
    {
        uint flags = AppInfoManager::get_instance().get_app_info_flags(payload_app_id,
            APPINFO_FLAG_SEARCH_ENGINE | APPINFO_FLAG_SUPPORTED_SEARCH);
        asd->search_support_type =
            (flags & APPINFO_FLAG_SEARCH_ENGINE) ?
            ((flags & APPINFO_FLAG_SUPPORTED_SEARCH) ? SUPPORTED_SEARCH_ENGINE :
            UNSUPPORTED_SEARCH_ENGINE )
            : NOT_A_SEARCH_ENGINE;
        if (asd->session_logging_enabled)
        {
            const char* typeString;
            switch ( asd->search_support_type )
            {
            case NOT_A_SEARCH_ENGINE: typeString = "NOT_A_SEARCH_ENGINE"; break;
            case SUPPORTED_SEARCH_ENGINE: typeString = "SUPPORTED_SEARCH_ENGINE"; break;
            case UNSUPPORTED_SEARCH_ENGINE: typeString = "UNSUPPORTED_SEARCH_ENGINE"; break;
            default: typeString = "unknown"; break;
            }

            LogMessage("AppIdDbg %s appId: %u (safe)search_support_type=%s\n",
                asd->session_logging_id, payload_app_id, typeString);
        }
    }

    if ( service_app_id !=  APP_ID_NONE )
    {
        if ( payload_app_id != APP_ID_NONE && payload_app_id != asd->past_indicator)
        {
            asd->past_indicator = payload_app_id;
            check_session_for_AF_indicator(p, direction, (ApplicationId)payload_app_id);
        }

        if (asd->payload_app_id == APP_ID_NONE && asd->past_forecast != service_app_id &&
            asd->past_forecast != APP_ID_UNKNOWN)
        {
            asd->past_forecast = check_session_for_AF_forecast(asd, p, direction,
                (ApplicationId)service_app_id);
        }
    }
}

