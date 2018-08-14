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

// appid_discovery.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_discovery.h"

#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

#include "app_forecast.h"
#include "appid_config.h"
#include "appid_debug.h"
#include "appid_detector.h"
#include "appid_dns_session.h"
#include "appid_http_session.h"
#include "appid_inspector.h"
#include "appid_session.h"
#include "appid_utils/ip_funcs.h"
#include "appid_utils/network_set.h"
#include "client_plugins/client_discovery.h"
#include "detector_plugins/detector_dns.h"
#include "detector_plugins/http_url_patterns.h"
#include "host_port_app_cache.h"
#include "service_plugins/service_discovery.h"
#ifdef ENABLE_APPID_THIRD_PARTY
#include "tp_lib_handler.h"
#include "tp_appid_utils.h"
#endif

using namespace snort;

AppIdDiscovery::AppIdDiscovery(AppIdInspector& ins)
    : inspector(ins)
{
    tcp_patterns = new SearchTool("ac_full", true);
    udp_patterns = new SearchTool("ac_full", true);
}

AppIdDiscovery::~AppIdDiscovery()
{
    for (auto pd : pattern_data )
        delete pd;

    pattern_data.clear();

    delete tcp_patterns;
    delete udp_patterns;

    for ( auto kv : tcp_detectors )
        delete kv.second;

    for ( auto kv : udp_detectors )
        delete kv.second;
}

void AppIdDiscovery::initialize_plugins(AppIdInspector* ins)
{
    ServiceDiscovery::get_instance(ins);
    ClientDiscovery::get_instance(ins);
}

void AppIdDiscovery::finalize_plugins()
{
    ServiceDiscovery::get_instance().finalize_service_patterns();
    ClientDiscovery::get_instance().finalize_client_plugins();
}

void AppIdDiscovery::release_plugins()
{
    ServiceDiscovery::release_instance();
    ClientDiscovery::release_instance();
}

void AppIdDiscovery::tterm()
{
    ClientDiscovery::get_instance().release_thread_resources();
    ServiceDiscovery::get_instance().release_thread_resources();
}

void AppIdDiscovery::register_detector(const std::string& name, AppIdDetector* cd,  IpProtocol proto)
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
    uint8_t* const pattern, unsigned size, unsigned nocase)
{
    AppIdPatternMatchNode* pd = new AppIdPatternMatchNode(detector, position, size);
    pattern_data.push_back(pd);
    st->add((const char*)pattern, size, pd, nocase);
}

void AppIdDiscovery::register_tcp_pattern(AppIdDetector* detector, const uint8_t* const pattern,
    unsigned size, int position, unsigned nocase)
{
    tcp_pattern_count++;
    add_pattern_data(detector, tcp_patterns, position, pattern, size, nocase);
}

void AppIdDiscovery::register_udp_pattern(AppIdDetector* detector, const uint8_t* const pattern,
    unsigned size, int position, unsigned nocase)
{
    udp_pattern_count++;
    add_pattern_data(detector, udp_patterns, position, pattern, size, nocase);
}

int AppIdDiscovery::add_service_port(AppIdDetector*, const ServiceDetectorPort&)
{
    return APPID_EINVALID;
}

void AppIdDiscovery::do_application_discovery(Packet* p, AppIdInspector& inspector)
{
    IpProtocol protocol = IpProtocol::PROTO_NOT_SET;
    AppidSessionDirection direction = APP_ID_FROM_INITIATOR;
    AppIdSession* asd = (AppIdSession*)p->flow->get_flow_data(AppIdSession::inspector_id);

    if ( !do_pre_discovery(p, &asd, inspector, protocol, direction) )
        return;

    AppId service_id;
    bool is_discovery_done = do_discovery(p, *asd, protocol, direction, service_id);

    do_post_discovery(p, *asd, direction, is_discovery_done, service_id);
}

static inline int match_pe_network(const SfIp* pktAddr, const PortExclusion* pe)
{
    const uint32_t* pkt = pktAddr->get_ip6_ptr();
    const uint32_t* nm = pe->netmask.u6_addr32;
    const uint32_t* peIP = pe->ip.u6_addr32;
    return (((pkt[0] & nm[0]) == peIP[0])
           && ((pkt[1] & nm[1]) == peIP[1])
           && ((pkt[2] & nm[2]) == peIP[2])
           && ((pkt[3] & nm[3]) == peIP[3]));
}

static inline int check_port_exclusion(const Packet* pkt, bool reversed, AppIdInspector& inspector)
{
    AppIdPortExclusions* src_port_exclusions;
    AppIdPortExclusions* dst_port_exclusions;
    SF_LIST* pe_list;
    PortExclusion* pe;
    const SfIp* s_ip;
    AppIdConfig* config = inspector.get_appid_config();

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
            if ( match_pe_network(s_ip, pe))
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
            if ( match_pe_network(s_ip, pe))
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
    AppIdConfig* config = AppIdInspector::get_inspector()->get_appid_config();
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
    AppidSessionDirection& direction)
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

        if (asd->common.initiator_port)
            direction = (asd->common.initiator_port == p->ptrs.sp) ?
                APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
        else
        {
            const SfIp* ip = p->ptrs.ip_api.get_src();
            direction = ip->fast_equals_raw(asd->common.initiator_ip) ?
                APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
        }

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

static bool is_packet_ignored(AppIdSession* asd, Packet* p, AppidSessionDirection direction)
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
        // FIXIT-M: In snort2x, a rebuilt packet was ignored whether it had a session or not.
        // Here, we are ignoring rebuilt packet only if it has a session. Why?
        if ( asd )
        {
            AppIdHttpSession* hsession = asd->get_http_session();
            if ( direction == APP_ID_FROM_INITIATOR && hsession && hsession->is_rebuilt_offsets() )
            {
                HttpPatternMatchers::get_instance()->get_http_offsets(p, hsession);
                if (appidDebug->is_active())
                {
                    uint16_t uri_start, uri_end, cookie_start, cookie_end;
                    hsession->get_offset(REQ_URI_FID, uri_start, uri_end);
                    hsession->get_offset(REQ_COOKIE_FID, cookie_start, cookie_end);
                    LogMessage(
                        "AppIdDbg %s Offsets from rebuilt packet: uri: %u-%u cookie: %u-%u\n",
                        appidDebug->get_debug_session(),
                        uri_start, uri_end, cookie_start, cookie_end);
                }
            }
            appid_stats.ignored_packets++;
            return true;
        }
    }

    return false;
}

static uint64_t is_session_monitored(AppIdSession& asd, const Packet* p, AppidSessionDirection dir,
    AppIdInspector& inspector)
{
    uint64_t flags;
    uint64_t flow_flags = APPID_SESSION_DISCOVER_APP;

    flow_flags |= asd.common.flags;
    // FIXIT-M - the 2.x purpose of this check is to stop monitoring a flow after a
    //           reload if the flow ip addresses are no longer configured to be
    //           monitored... this may not apply in snort++, find out and fix
    //           accordingly
    if ( asd.common.policyId != asd.config->appIdPolicyId )
    {
        if ( check_port_exclusion(p, dir == APP_ID_FROM_RESPONDER, inspector) )
        {
            flow_flags |= APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_RESPONDER_CHECKED;
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

static uint64_t is_session_monitored(const Packet* p, AppidSessionDirection dir,
    AppIdInspector& inspector)
{
    uint64_t flags = 0;
    uint64_t flow_flags = APPID_SESSION_DISCOVER_APP;

    if ( check_port_exclusion(p, false, inspector) )
    {
        flow_flags |= APPID_SESSION_INITIATOR_CHECKED | APPID_SESSION_RESPONDER_CHECKED;
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

static void lookup_appid_by_host_port(AppIdSession& asd, Packet* p, IpProtocol protocol,
    AppidSessionDirection direction)
{
    HostPortVal* hv = nullptr;
    uint16_t port = 0;
    const SfIp* ip = nullptr;
    asd.scan_flags |= SCAN_HOST_PORT_FLAG;
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
            asd.client.set_id(hv->appId);
            asd.client_disco_state = APPID_DISCO_STATE_FINISHED;
            break;
        case 2:
            asd.payload.set_id(hv->appId);
            break;
        default:
            asd.service.set_id(hv->appId);
            asd.sync_with_snort_protocol_id(hv->appId, p);
            asd.service_disco_state = APPID_DISCO_STATE_FINISHED;
            asd.client_disco_state = APPID_DISCO_STATE_FINISHED;
            asd.set_session_flags(APPID_SESSION_SERVICE_DETECTED);
#ifdef ENABLE_THIRD_PARTY_APPID
            if (asd.tpsession)
                asd.tpsession->reset();
#endif
            if ( asd.payload.get_id() == APP_ID_NONE)
                asd.payload.set_id(APP_ID_UNKNOWN);
        }
    }
}

bool AppIdDiscovery::handle_unmonitored_session(AppIdSession* asd, const Packet* p,
    IpProtocol protocol, AppidSessionDirection dir, AppIdInspector& inspector,
    uint64_t& flow_flags)
{
    if (asd)
        flow_flags = is_session_monitored(*asd, p, dir, inspector);
    else
        flow_flags = is_session_monitored(p, dir, inspector);

    if ( flow_flags & (APPID_SESSION_DISCOVER_APP | APPID_SESSION_SPECIAL_MONITORED) )
        return false;

    if ( !asd )
    {
        uint16_t port = 0;

        const SfIp* ip = (dir == APP_ID_FROM_INITIATOR) ?
            p->ptrs.ip_api.get_src() : p->ptrs.ip_api.get_dst();
        if ((protocol == IpProtocol::TCP || protocol == IpProtocol::UDP)
            && p->ptrs.sp != p->ptrs.dp)
        {
            port = (dir == APP_ID_FROM_INITIATOR) ? p->ptrs.sp : p->ptrs.dp;
        }

        // FIXIT-H - Creating AppId session even when flow is ignored (not monitored, e.g.,
        // when AppId discovery is disabled) will consume a lot of unneeded memory and perform
        // unneeded tasks in constructor. Snort2 uses static APPID_SESSION_STRUCT_FLAG ignore_fsf.
        // Snort3 may use something like that or a dummy class/object having only common.flow_type
        // to let us know that it is APPID_FLOW_TYPE_IGNORE type and thus being returned early
        // from this method due to set_network_attributes() checking.
        AppIdSession* tmp_session = new AppIdSession(protocol, ip, port, inspector);

        if ((flow_flags & APPID_SESSION_BIDIRECTIONAL_CHECKED) ==
            APPID_SESSION_BIDIRECTIONAL_CHECKED)
        {
            tmp_session->common.flow_type = APPID_FLOW_TYPE_IGNORE;
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s Not monitored\n", appidDebug->get_debug_session());
        }
        else
        {
            tmp_session->common.flow_type = APPID_FLOW_TYPE_TMP;
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s Unknown monitoring\n", appidDebug->get_debug_session());
        }
        tmp_session->common.flags = flow_flags;
        tmp_session->common.policyId = inspector.get_appid_config()->appIdPolicyId;
        p->flow->set_flow_data(tmp_session);
    }
    else
    {
        asd->common.flags = flow_flags;
        if ( ( flow_flags & APPID_SESSION_BIDIRECTIONAL_CHECKED) ==
            APPID_SESSION_BIDIRECTIONAL_CHECKED )
            asd->common.flow_type = APPID_FLOW_TYPE_IGNORE;
        asd->common.policyId = asd->config->appIdPolicyId;
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s Not monitored\n", appidDebug->get_debug_session());
    }

    return true;
}

// Return false if the packet or the session doesn't need to be inspected
bool AppIdDiscovery::do_pre_discovery(Packet* p, AppIdSession** p_asd, AppIdInspector& inspector,
    IpProtocol& protocol, AppidSessionDirection& direction)
{
    AppIdSession* asd = *p_asd;

    if ( !set_network_attributes(asd, p, protocol, direction) )
    {
        appid_stats.ignored_packets++;
        return false;
    }

    if ( appidDebug->is_enabled() )
        appidDebug->activate(p->flow, asd,
            inspector.get_appid_config()->mod_config->log_all_sessions);

    if ( is_packet_ignored(asd, p, direction) )
        return false;

    uint64_t flow_flags;
    if ( handle_unmonitored_session(asd, p, protocol, direction, inspector, flow_flags) )
        return false;

    // FIXIT-M - Potential memory leak for TMP sessions. handle_unmonitored_session() already
    // TMP session and that is not being freed before creating the new one below
    if ( !asd || asd->common.flow_type == APPID_FLOW_TYPE_TMP )
    {
        *p_asd = asd = AppIdSession::allocate_session(p, protocol, direction, inspector);
        if (p->flow->get_session_flags() & SSNFLAG_MIDSTREAM)
        {
            asd->set_session_flags(APPID_SESSION_MID);
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s New AppId mid-stream session\n",
                    appidDebug->get_debug_session());
        }
        else if (appidDebug->is_active())
            LogMessage("AppIdDbg %s New AppId session\n", appidDebug->get_debug_session());
    }

    // FIXIT-L - from this point on we always have a valid ptr to a Packet
    //           refactor to pass this as ref and delete any checks for null
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
        if (!asd->get_session_flags(APPID_SESSION_IGNORE_FLOW_IDED))
        {
            asd->set_application_ids(asd->pick_service_app_id(), asd->pick_client_app_id(),
                asd->pick_payload_app_id(), asd->pick_misc_app_id());
            asd->set_session_flags(APPID_SESSION_IGNORE_FLOW_IDED);
        }

        if (appidDebug->is_active() &&
            !asd->get_session_flags(APPID_SESSION_IGNORE_FLOW_LOGGED))
        {
            asd->set_session_flags(APPID_SESSION_IGNORE_FLOW_LOGGED);

            const char *app_name = AppInfoManager::get_instance().get_app_name(asd->service.get_id());
            LogMessage("AppIdDbg %s Ignoring connection with service %s (%d)\n",
                appidDebug->get_debug_session(), app_name ? app_name : "unknown", asd->service.get_id());
        }

        return false;
    }

    if (p->ptrs.tcph and !asd->get_session_flags(APPID_SESSION_OOO))
    {
        if ((p->packet_flags & PKT_STREAM_ORDER_BAD) ||
            (p->dsize && !(p->packet_flags & (PKT_STREAM_ORDER_OK | PKT_REBUILT_STREAM))))
        {
            asd->set_session_flags(APPID_SESSION_OOO);
            if (appidDebug->is_active())
                LogMessage("AppIdDbg %s Packet out-of-order, %s%sflow\n",
                    appidDebug->get_debug_session(),
                    (p->packet_flags & PKT_STREAM_ORDER_BAD) ? "bad " : "not-ok ",
                    asd->get_session_flags(APPID_SESSION_MID) ? "mid-stream " : "");

            // Shut off service/client discoveries, since they skip not-ok data packets and
            // may keep failing on subsequent data packets causing performance degradation
            if (!asd->get_session_flags(APPID_SESSION_MID) ||
                (p->ptrs.sp != 21 && p->ptrs.dp != 21)) // exception for ftp-control
            {
                asd->service_disco_state = APPID_DISCO_STATE_FINISHED;
                asd->client_disco_state = APPID_DISCO_STATE_FINISHED;
                asd->set_session_flags(APPID_SESSION_SERVICE_DETECTED |
                    APPID_SESSION_CLIENT_DETECTED);
                if (appidDebug->is_active())
                    LogMessage("AppIdDbg %s stopped service/client discovery\n",
                        appidDebug->get_debug_session());
            }
        }
        else
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

                AppIdServiceState::check_reset(*asd, ip, port);
            }

            asd->previous_tcp_flags = p->ptrs.tcph->th_flags;
        }
    }

    // FIXIT-L: DECRYPT_DEBUG - Move set_proxied and first_decrypted_packet_debug to ssl-module
    // after ssl-module's decryption capability is implemented
#ifdef REG_TEST
    uint32_t fdpd = inspector.get_appid_config()->mod_config->first_decrypted_packet_debug;
    if (fdpd and (fdpd == asd->session_packet_count))
    {
        p->flow->set_proxied();
        if (appidDebug->is_active())
            LogMessage("AppIdDbg %s Marked the flow as decrypted at packet number %lu\n",
                appidDebug->get_debug_session(), (long unsigned)fdpd);
    }
#endif

    return true;
}

bool AppIdDiscovery::do_discovery(Packet* p, AppIdSession& asd, IpProtocol protocol,
    AppidSessionDirection direction, AppId& service_id)
{
    bool is_discovery_done = false;

    // {host, port} based detection
    if ( !(asd.scan_flags & SCAN_HOST_PORT_FLAG) )
        lookup_appid_by_host_port(asd, p, protocol, direction);

    asd.check_app_detection_restart();

    // Third party detection
#ifdef ENABLE_APPID_THIRD_PARTY
    if ( TPLibHandler::have_tp() )
        is_discovery_done = do_tp_discovery(asd,protocol,p,direction);
#endif

    // Port-based service detection
    if ( !asd.get_session_flags(APPID_SESSION_PORT_SERVICE_DONE) )
    {
        switch (protocol)
        {
        case IpProtocol::TCP:
            if (asd.get_session_flags(APPID_SESSION_SYN_RST)) // TCP-specific exception
                break;
        // fallthrough
        case IpProtocol::UDP:
            // Both TCP and UDP need this test to be made
            // against only the p->src_port of the response.
            // For all other cases the port parameter is never checked.
            if (direction != APP_ID_FROM_RESPONDER)
                break;
        // fallthrough
        // All protocols other than TCP and UDP come straight here.
        default:
        {
            AppId id = asd.config->get_port_service_id(protocol, p->ptrs.sp);
            if (id > APP_ID_NONE)
            {
                asd.service.set_port_service_id(id);
                if (appidDebug->is_active())
                {
                    const char *app_name = AppInfoManager::get_instance().get_app_name(asd.service.get_port_service_id());
                    LogMessage("AppIdDbg %s Port service %s (%d) from port\n",
                        appidDebug->get_debug_session(), app_name ? app_name : "unknown", asd.service.get_port_service_id());
                }
            }
            asd.set_session_flags(APPID_SESSION_PORT_SERVICE_DONE);
        }
        break;
        }
    }

    // exceptions for rexec and any other service detector that need to see SYN and SYN/ACK
    if (asd.get_session_flags(APPID_SESSION_REXEC_STDERR))
    {
        ServiceDiscovery::get_instance().identify_service(asd, p, direction);
        AppIdDnsSession* dsession = asd.get_dns_session();

        if (asd.service.get_id() == APP_ID_DNS &&
            asd.config->mod_config->dns_host_reporting && dsession->get_host() )
        {
            AppId client_id = APP_ID_NONE, payload_id = APP_ID_NONE;
            dns_host_scan_hostname((const uint8_t*)dsession->get_host(), dsession->get_host_len(),
                &client_id, &payload_id);
            asd.set_client_appid_data(client_id, nullptr);
        }
        else if (asd.service.get_id() == APP_ID_RTMP)
            asd.examine_rtmp_metadata();
        else if (asd.get_session_flags(APPID_SESSION_SSL_SESSION) && asd.tsession)
            asd.examine_ssl_metadata(p);
    }
    // FIXIT-M - snort 2.x has added a check for midstream pickup to this, do we need that?
    else if (protocol != IpProtocol::TCP || (p->packet_flags & PKT_STREAM_ORDER_OK))
    {
        if (asd.service_disco_state != APPID_DISCO_STATE_FINISHED)
            is_discovery_done =
                ServiceDiscovery::get_instance().do_service_discovery(asd, p, direction);
        if (asd.client_disco_state != APPID_DISCO_STATE_FINISHED)
            is_discovery_done =
                ClientDiscovery::get_instance().do_client_discovery(asd, p, direction);
        asd.set_session_flags(APPID_SESSION_ADDITIONAL_PACKET);
    }

    service_id = asd.pick_service_app_id();

    // Length-based service detection if no service is found yet
    if ( (service_id <= APP_ID_NONE or service_id == APP_ID_UNKNOWN_UI) and (p->dsize > 0) and
         (asd.length_sequence.sequence_cnt < LENGTH_SEQUENCE_CNT_MAX) and
         !asd.get_session_flags(APPID_SESSION_OOO) )
    {
        uint8_t index = asd.length_sequence.sequence_cnt;
        asd.length_sequence.proto = protocol;
        asd.length_sequence.sequence_cnt++;
        asd.length_sequence.sequence[index].direction = direction;
        asd.length_sequence.sequence[index].length = p->dsize;
        AppId id = find_length_app_cache(asd.length_sequence);
        if (id > APP_ID_NONE)
        {
            service_id = id;
            asd.service.set_port_service_id(id);
            if (appidDebug->is_active())
            {
                const char *app_name = AppInfoManager::get_instance().get_app_name(id);
                LogMessage("AppIdDbg %s Port service %s (%d) from length\n",
                    appidDebug->get_debug_session(), app_name ? app_name : "unknown", id);
            }
            asd.set_session_flags(APPID_SESSION_PORT_SERVICE_DONE);
        }
    }

    return is_discovery_done;
}

void AppIdDiscovery::do_post_discovery(Packet* p, AppIdSession& asd,
    AppidSessionDirection direction, bool is_discovery_done, AppId service_id)
{
    AppId payload_id = asd.pick_payload_app_id();

    if (service_id > APP_ID_NONE)
    {
        if (asd.get_session_flags(APPID_SESSION_DECRYPTED))
        {
            if (asd.misc_app_id == APP_ID_NONE)
                asd.update_encrypted_app_id(service_id);
        }
// FIXIT-M Need to determine what api to use for this _dpd function
#if 1
        UNUSED(is_discovery_done);
#else
        else if (is_discovery_done && isSslServiceAppId(service_id) &&
            _dpd.isSSLPolicyEnabled(nullptr))
            asd.set_session_flags(APPID_SESSION_CONTINUE);
#endif
    }

    asd.set_application_ids(service_id, asd.pick_client_app_id(), payload_id,
        asd.pick_misc_app_id());

    // Set the field that the Firewall queries to see if we have a search engine
    if (asd.search_support_type == UNKNOWN_SEARCH_ENGINE && payload_id > APP_ID_NONE)
    {
        uint flags = AppInfoManager::get_instance().get_app_info_flags(payload_id,
            APPINFO_FLAG_SEARCH_ENGINE | APPINFO_FLAG_SUPPORTED_SEARCH);
        asd.search_support_type =
            (flags & APPINFO_FLAG_SEARCH_ENGINE) ?
            ((flags & APPINFO_FLAG_SUPPORTED_SEARCH) ? SUPPORTED_SEARCH_ENGINE :
            UNSUPPORTED_SEARCH_ENGINE )
            : NOT_A_SEARCH_ENGINE;
        if (appidDebug->is_active())
        {
            const char* typeString;
            const char *app_name = AppInfoManager::get_instance().get_app_name(payload_id);
            switch ( asd.search_support_type )
            {
            case NOT_A_SEARCH_ENGINE: typeString = "NOT_A_SEARCH_ENGINE"; break;
            case SUPPORTED_SEARCH_ENGINE: typeString = "SUPPORTED_SEARCH_ENGINE"; break;
            case UNSUPPORTED_SEARCH_ENGINE: typeString = "UNSUPPORTED_SEARCH_ENGINE"; break;
            default: typeString = "unknown"; break;
            }
            LogMessage("AppIdDbg %s Application: %s (%d) (safe)search_support_type=%s\n",
                appidDebug->get_debug_session(), app_name ? app_name : "unknown", payload_id, typeString);
        }
    }

    if ( service_id !=  APP_ID_NONE )
    {
        if ( payload_id != APP_ID_NONE && payload_id != asd.past_indicator)
        {
            asd.past_indicator = payload_id;
            check_session_for_AF_indicator(p, direction, (AppId)payload_id);
        }

        if (asd.payload.get_id() == APP_ID_NONE && asd.past_forecast != service_id &&
            asd.past_forecast != APP_ID_UNKNOWN)
        {
            asd.past_forecast = check_session_for_AF_forecast(asd, p, direction,
                (AppId)service_id);
            asd.set_application_ids(service_id, asd.pick_client_app_id(),
                asd.pick_payload_app_id(), asd.pick_misc_app_id());
        }
    }
}

