/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2005-2013 Sourcefire, Inc.
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

#include "stream_icmp.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "icmp_module.h"
#include "icmp_session.h"
#include "snort_types.h"
#include "snort_debug.h"
#include "protocols/packet.h"
#include "mstring.h"
#include "sfxhash.h"
#include "util.h"
#include "stream/stream.h"
#include "flow/flow.h"
#include "flow/flow_control.h"
#include "flow/session.h"
#include "perf_monitor/perf.h"
#include "profiler.h"
#include "protocols/layer.h"
#include "protocols/vlan.h"
#include "protocols/ip.h"
#include "protocols/icmp4.h"
#include "sfip/sf_ip.h"

THREAD_LOCAL SessionStats icmpStats;
THREAD_LOCAL ProfileStats icmp_perf_stats;

//------------------------------------------------------------------------
// private functions
//------------------------------------------------------------------------

static void IcmpSessionCleanup(Flow *ssn)
{
    if (ssn->s5_state.session_flags & SSNFLAG_PRUNED)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_PRUNED);
    }
    else if (ssn->s5_state.session_flags & SSNFLAG_TIMEDOUT)
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_TIMEDOUT);
    }
    else
    {
        CloseStreamSession(&sfBase, SESSION_CLOSED_NORMALLY);
    }

    ssn->clear();

    icmpStats.released++;
}

static int ProcessIcmpUnreach(Packet *p)
{
    /* Handle ICMP unreachable */
    FlowKey skey;
    Flow* ssn = NULL;
    uint16_t sport;
    uint16_t dport;
    const sfip_t *src;
    const sfip_t *dst;
    ip::IpApi iph;

    /* Set the Ip API to the embedded IP Header. */
    if (!layer::set_api_ip_embed_icmp(p, iph))
        return 0;

    /* Get IP/TCP/UDP/ICMP session from original protocol/port info
     * embedded in the ICMP Unreach message.
     */
    skey.protocol = p->type();
    src = iph.get_src();
    dst = iph.get_dst();


    if (p->proto_bits & PROTO_BIT__TCP_EMBED_ICMP)
    {
        const tcp::TCPHdr* tcph = layer::get_tcp_embed_icmp(iph);
        sport = ntohs(tcph->th_sport);
        dport = ntohs(tcph->th_dport);
    }
    else if (p->proto_bits & PROTO_BIT__UDP_EMBED_ICMP)
    {
        const udp::UDPHdr* udph = layer::get_udp_embed_icmp(iph);

        sport = ntohs(udph->uh_sport);
        dport = ntohs(udph->uh_dport);
    }
    else
    {
        sport = 0;
        dport = 0;
    }



    if (sfip_fast_lt6(src, dst))
    {
        COPY4(skey.ip_l, src->ip32);
        skey.port_l = sport;
        COPY4(skey.ip_h, dst->ip32);
        skey.port_h = dport;
    }
    else if (sfip_equals(iph.get_src(), iph.get_dst()))
    {
        COPY4(skey.ip_l, src->ip32);
        COPY4(skey.ip_h, skey.ip_l);
        if (sport < dport)
        {
            skey.port_l = sport;
            skey.port_h = dport;
        }
        else
        {
            skey.port_l = dport;
            skey.port_h = sport;
        }
    }
    else
    {
        COPY4(skey.ip_l, dst->ip32);
        COPY4(skey.ip_h, src->ip32);
        skey.port_l = dport;
        skey.port_h = sport;
    }

    if (p->proto_bits & PROTO_BIT__VLAN)
        skey.vlan_tag = layer::get_vlan_layer(p)->vid();
    else
        skey.vlan_tag = 0;

    switch (skey.protocol)
    {
    case PktType::TCP:
        /* Lookup a TCP session */
        ssn = Stream::get_session(&skey);
        break;
    case PktType::UDP:
        /* Lookup a UDP session */
        ssn = Stream::get_session(&skey);
        break;
    case PktType::ICMP:
        /* Lookup a ICMP session */
        ssn = Stream::get_session(&skey);
        break;
    default:
        break;
    }

    if (ssn)
    {
        /* Mark this session as dead. */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Marking session as dead, per ICMP Unreachable!\n"););
        ssn->s5_state.session_flags |= SSNFLAG_DROP_CLIENT;
        ssn->s5_state.session_flags |= SSNFLAG_DROP_SERVER;
        ssn->session_state |= STREAM5_STATE_UNREACH;
    }

    return 0;
}

//-------------------------------------------------------------------------
// IcmpSession methods
//-------------------------------------------------------------------------

IcmpSession::IcmpSession(Flow* flow) : Session(flow)
{
    setup(nullptr);
}

bool IcmpSession::setup(Packet*)
{
    echo_count = 0;
    ssn_time.tv_sec = 0;
    ssn_time.tv_usec = 0;
    return true;
}

void IcmpSession::clear()
{
    IcmpSessionCleanup(flow);
}

int IcmpSession::process(Packet* p)
{
    int status;

    switch (p->ptrs.icmph->type)
    {
    case ICMP_DEST_UNREACH:
        status = ProcessIcmpUnreach(p);
        break;

    default:
        /* We only handle the above ICMP messages with stream5 */
        status = 0;
        break;
    }

    return status;
}

#define icmp_sender_ip flow->client_ip
#define icmp_responder_ip flow->server_ip

void IcmpSession::update_direction(char dir, const sfip_t *ip, uint16_t)
{
    if (sfip_equals(&icmp_sender_ip, ip))
    {
        if ((dir == SSN_DIR_SENDER) && (flow->s5_state.direction == SSN_DIR_SENDER))
        {
            /* Direction already set as SENDER */
            return;
        }
    }
    else if (sfip_equals(&icmp_responder_ip, ip))
    {
        if ((dir == SSN_DIR_RESPONDER) && (flow->s5_state.direction == SSN_DIR_RESPONDER))
        {
            /* Direction already set as RESPONDER */
            return;
        }
    }

    /* Swap them -- leave ssn->s5_state.direction the same */
    sfip_t tmpIp = icmp_sender_ip;
    icmp_sender_ip = icmp_responder_ip;
    icmp_responder_ip = tmpIp;
}

//-------------------------------------------------------------------------
// api related methods
//-------------------------------------------------------------------------

#if 0
void icmp_stats()
{
    // FIXIT-L move these to the actual owner
    // FIXIT-L need to get these before delete flow_con
    //flow_con->get_prunes(IPPROTO_UDP, icmpStats.prunes);
}
#endif

void icmp_reset()
{
    memset(&icmpStats, 0, sizeof(icmpStats));
    flow_con->reset_prunes(PktType::ICMP);
}

