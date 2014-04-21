/****************************************************************************
 *
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2013-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#include "flow/flow_control.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "flow/flow_cache.h"
#include "flow/expect_cache.h"
#include "flow/session.h"

#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "stream5/stream_tcp.h"
#include "stream5/stream_udp.h"
#include "stream5/stream_icmp.h"
#include "stream5/stream_ip.h"
#include "stream5/stream_ha.h"

FlowControl::FlowControl(const Stream5Config* s5)
{
    init_tcp(s5);
    init_udp(s5);
    init_icmp(s5);
    init_ip(s5);
    init_exp(s5);
}

FlowControl::~FlowControl()
{
    delete tcp_cache;
    delete udp_cache;
    delete icmp_cache;
    delete ip_cache;
    delete exp_cache;
}

//-------------------------------------------------------------------------
// cache foo
//-------------------------------------------------------------------------

inline FlowCache* FlowControl::get_cache (int proto)
{
    switch ( proto ) {
    case IPPROTO_TCP:  return tcp_cache;
    case IPPROTO_UDP:  return udp_cache;
    case IPPROTO_ICMP: return icmp_cache;
    case IPPROTO_IP:   return ip_cache;
    }
    return NULL;
}

Flow* FlowControl::get_flow (const FlowKey* key)
{
    FlowCache* cache = get_cache(key->protocol);

    if ( cache )
        return cache->get(key);

    return NULL;
}

Flow* FlowControl::new_flow (const FlowKey* key)
{
    Stream5Config* s5 = (Stream5Config*)get_inspection_policy()->s5_config;
    FlowCache* cache = get_cache(key->protocol);

    if ( !s5 || !cache )
        return NULL;

    bool init = true;
    return cache->get(s5, key, init);
}

// FIXIT cache* can be put in flow so that lookups by
// protocol are obviated for existing / initialized flows
void FlowControl::delete_flow (const FlowKey* key)
{
    FlowCache* cache = get_cache(key->protocol);

    if ( !cache )
        return;

    Flow* flow = cache->get(key);

    if ( flow )
        cache->release(flow, "ha sync");
}

void FlowControl::delete_flow (Flow* flow, const char* why)
{
    FlowCache* cache = get_cache(flow->protocol);

    if ( cache )
        cache->release(flow, why);
}

void FlowControl::purge_flows (int proto)
{
    FlowCache* cache = get_cache(proto);

    if ( cache )
        cache->purge();
}

void FlowControl::prune_flows (int proto, Packet* p)
{
    FlowCache* cache = get_cache(proto);

    if ( !cache )
        return;

    // smack the older timed out flows
    if (!cache->prune_stale(p->pkth->ts.tv_sec, (Flow*)p->flow))
    {
        // if no luck, try the memcap
        cache->prune_excess(true, (Flow*)p->flow);
    }
}

void FlowControl::timeout_flows(uint32_t flowCount, time_t cur_time)
{
    Active_Suspend();

    if ( tcp_cache )
        tcp_cache->timeout(flowCount, cur_time);

    if ( udp_cache )
        udp_cache->timeout(flowCount, cur_time);

    //if ( icmp_cache )
    //icmp_cache does not need cleaning

    if ( ip_cache )
        ip_cache->timeout(flowCount, cur_time);

    Active_Resume();
}

uint32_t FlowControl::max_flows(int proto)
{
    FlowCache* cache = get_cache(proto);

    if ( cache )
        return cache->get_max_flows();

    return 0;
}

void FlowControl::get_prunes (int proto, PegCount& prunes)
{
    FlowCache* cache = get_cache(proto);

    if ( cache )
        prunes = cache->get_prunes();
}

void FlowControl::reset_prunes (int proto)
{
    FlowCache* cache = get_cache(proto);

    if ( cache )
        cache->reset_prunes();
}

void FlowControl::set_key(FlowKey* key, const Packet* p)
{
    char proto = GET_IPH_PROTO(p);
    uint32_t mplsId = 0;
    uint16_t vlanId = 0;
    uint16_t sport = p->sp;
    uint16_t addressSpaceId = 0;

    if (ScMplsOverlappingIp() && (p->mpls != NULL))
    {
        mplsId = p->mplsHdr.label;
    }
#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    addressSpaceId = DAQ_GetAddressSpaceID(p->pkth);
#endif

    if (p->vh && !ScVlanAgnostic())
        vlanId = (uint16_t)VTH_VLAN(p->vh);
    if ((proto == IPPROTO_ICMP) || (proto == IPPROTO_ICMPV6))
    {
        /* ICMP */
        sport = p->icmph->type;
    }
    key->init(GET_SRC_IP(p), sport,
        GET_DST_IP(p), p->dp,
        proto, vlanId, mplsId, addressSpaceId);
}

static bool is_bidirectional(Flow* flow)
{
    constexpr unsigned bidir = SSNFLAG_SEEN_CLIENT | SSNFLAG_SEEN_SERVER;
    return (flow->s5_state.session_flags & bidir) == bidir;
}

void FlowControl::process(
    FlowCache* cache, Stream5Config* config, void* pv, Packet* p)
{
    FlowKey key;
    set_key(&key, p);

    bool init = true;
    Flow* flow = cache->get(config, &key, init);

    if ( !flow )
        return;

    if ( !flow->policy )
    {
        if ( !init )
            return;

        else
        {
            // FIXIT stream port filter broken?
            //if ( Stream::get_filter_status(config, p) )
            //    return;

            // FIXIT these are separate from init; will be moved out of preproc
            // into external NAP lookup encapsulated here
            flow->policy = flow->session->get_policy(pv, p);

            if ( !flow->policy )
                return;

            if ( !flow->session->setup(p) )
            {
                flow->policy = NULL;
                return;
            }
        }
    }

#ifdef ENABLE_HA
    Stream5State old_s5_state = flow->s5_state;
#endif
    p->flow = flow;
    flow->session->process(p);

    if ( init && is_bidirectional(flow) )
        cache->unlink_uni(flow);

    ha_state_diff(flow, &old_s5_state);
}

//-------------------------------------------------------------------------
// tcp
//-------------------------------------------------------------------------

#ifdef ENABLE_HA
#define enable_ha(s5) s5->ha_config
#else
#define enable_ha(s5) false
#endif

void FlowControl::init_tcp(const Stream5Config* s5)
{
    const Stream5GlobalConfig* pc = s5->global_config;

    if ( !pc->max_tcp_sessions )
    {
        tcp_cache = nullptr;
        return;
    }
    tcp_cache = new FlowCache(
        pc->max_tcp_sessions, pc->tcp_cache_pruning_timeout,
        pc->tcp_cache_nominal_timeout, 5, 0);

    for ( unsigned i = 0; i < pc->max_tcp_sessions; ++i )
    {
        Flow* flow = new Flow(IPPROTO_TCP, enable_ha(s5));
        flow->session = get_tcp_session(flow);
        tcp_cache->push(flow);
    }
}

void FlowControl::process_tcp(Stream5Config* config, Packet* p)
{
    if( !p->tcph || !tcp_cache )
        return;

    process(tcp_cache, config, config->tcp_config, p);
}

//-------------------------------------------------------------------------
// udp
//-------------------------------------------------------------------------

void FlowControl::init_udp(const Stream5Config* s5)
{
    const Stream5GlobalConfig* pc = s5->global_config;

    if ( !pc->max_udp_sessions )
    {
        udp_cache = nullptr;
        return;
    }
    udp_cache = new FlowCache(
        pc->max_udp_sessions, pc->udp_cache_pruning_timeout,
        pc->udp_cache_nominal_timeout, 5, 0);

    for ( unsigned i = 0; i < pc->max_udp_sessions; ++i )
    {
        Flow* flow = new Flow(IPPROTO_UDP, enable_ha(s5));
        flow->session = get_udp_session(flow);
        udp_cache->push(flow);
    }
}

void FlowControl::process_udp(Stream5Config* config, Packet* p)
{
    if( !p->udph || !udp_cache )
        return;

    process(udp_cache, config, config->udp_config, p);
}

//-------------------------------------------------------------------------
// icmp
//-------------------------------------------------------------------------

void FlowControl::init_icmp(const Stream5Config* s5)
{
    const Stream5GlobalConfig* pc = s5->global_config;

    if ( !pc->max_icmp_sessions )
    {
        icmp_cache = nullptr;
        return;
    }
    icmp_cache = new FlowCache(pc->max_icmp_sessions, 30, 30, 5, 0);

    for ( unsigned i = 0; i < pc->max_icmp_sessions; ++i )
    {
        Flow* flow = new Flow(IPPROTO_ICMP, enable_ha(s5));
        flow->session = get_icmp_session(flow);
        icmp_cache->push(flow);
    }
}

void FlowControl::process_icmp(Stream5Config* config, Packet* p)
{
    if ( !p->icmph )
        return;

    if ( config->global_config->max_icmp_sessions )
        process(icmp_cache, config, config->icmp_config, p);

    else
        process_ip(config, p);
}

//-------------------------------------------------------------------------
// ip
//-------------------------------------------------------------------------

void FlowControl::init_ip(const Stream5Config* s5)
{
    const Stream5GlobalConfig* pc = s5->global_config;

    if ( !pc->max_ip_sessions )
    {
        ip_cache = nullptr;
        return;
    }
    ip_cache = new FlowCache(pc->max_ip_sessions, 30, 30, 5, 0);

    for ( unsigned i = 0; i < pc->max_ip_sessions; ++i )
    {
        Flow* flow = new Flow(IPPROTO_IP, enable_ha(s5));
        flow->session = get_ip_session(flow);
        ip_cache->push(flow);
    }
}

void FlowControl::process_ip(Stream5Config* config, Packet* p)
{
    if ( !p->iph || !ip_cache )
        return;

    process(ip_cache, config, config->ip_config, p);
}

//-------------------------------------------------------------------------
// expected
//-------------------------------------------------------------------------

void FlowControl::init_exp(const Stream5Config* config)
{
    uint32_t max =
        config->global_config->max_tcp_sessions +
        config->global_config->max_udp_sessions;

    max >>= 9;
    if ( !max )
        max = 2;

    exp_cache = new ExpectCache(max);
}

char FlowControl::expected_flow (Flow* flow, Packet* p)
{
    char ignore = exp_cache->check(p, flow);

    if ( ignore )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream5: Ignoring packet from %d. Marking flow marked as ignore.\n",
            p->packet_flags & PKT_FROM_CLIENT? "sender" : "responder"););

        flow->s5_state.ignore_direction = ignore;
        DisableInspection(p);
    }

    return ignore;
}

int FlowControl::add_expected(
    snort_ip_p srcIP, uint16_t srcPort,
    snort_ip_p dstIP, uint16_t dstPort,
    uint8_t protocol, char direction,
    FlowData* fd)
{
    return exp_cache->add_flow(
        srcIP, srcPort, dstIP, dstPort, protocol, direction, fd);
}

int FlowControl::add_expected(
    snort_ip_p srcIP, uint16_t srcPort,
    snort_ip_p dstIP, uint16_t dstPort,
    uint8_t protocol, int16_t appId,
    FlowData* fd)
{
    return exp_cache->add_flow(
        srcIP, srcPort, dstIP, dstPort, protocol, SSN_DIR_BOTH, fd, appId);
}

bool FlowControl::is_expected(Packet* p)
{
    return exp_cache->is_expected(p);
}

