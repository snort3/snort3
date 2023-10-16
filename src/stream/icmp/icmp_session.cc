//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "icmp_session.h"

#include "detection/ips_context.h"
#include "flow/flow_key.h"
#include "profiler/profiler_defs.h"
#include "protocols/icmp4.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/vlan.h"
#include "pub_sub/stream_event_ids.h"
#include "stream/stream.h"
#include "utils/util.h"

#include "icmp_ha.h"
#include "icmp_module.h"
#include "stream_icmp.h"

using namespace snort;

const PegInfo icmp_pegs[] =
{
    SESSION_PEGS("icmp"),
    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL IcmpStats icmpStats;
THREAD_LOCAL ProfileStats icmp_perf_stats;

//------------------------------------------------------------------------
// private functions
//------------------------------------------------------------------------

static void IcmpSessionCleanup(Flow* ssn)
{
    if ( ssn->ssn_state.session_flags & SSNFLAG_SEEN_SENDER )
        icmpStats.released++;

    ssn->clear();
}

static int ProcessIcmpUnreach(Packet* p)
{
    /* Handle ICMP unreachable */
    FlowKey skey;
    Flow* ssn = nullptr;
    uint16_t sport;
    uint16_t dport;
    const SfIp* src;
    const SfIp* dst;
    ip::IpApi iph;
    bool reversed = false;

    /* Set the Ip API to the embedded IP Header. */
    if (!layer::set_api_ip_embed_icmp(p, iph))
        return 0;

    /* Get IP/TCP/UDP/ICMP session from original protocol/port info
     * embedded in the ICMP Unreach message.
     */
    src = iph.get_src();
    dst = iph.get_dst();

    skey.pkt_type = p->type();
    skey.version = src->is_ip4() ? 4 : 6;
    skey.ip_protocol = (uint8_t)p->get_ip_proto_next();

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

    if (src->fast_lt6(*dst))
    {
        COPY4(skey.ip_l, src->get_ip6_ptr());
        skey.port_l = sport;
        COPY4(skey.ip_h, dst->get_ip6_ptr());
        skey.port_h = dport;
    }
    else if (iph.get_src()->equals(*iph.get_dst()))
    {
        COPY4(skey.ip_l, src->get_ip6_ptr());
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
            reversed = true;
        }
    }
    else
    {
        COPY4(skey.ip_l, dst->get_ip6_ptr());
        COPY4(skey.ip_h, src->get_ip6_ptr());
        skey.port_l = dport;
        skey.port_h = sport;
        reversed = true;
    }

    uint16_t vlan = (p->proto_bits & PROTO_BIT__VLAN) ?
        layer::get_vlan_layer(p)->vid() : 0;

    // FIXIT-L see FlowKey::init*() - call those instead
    // or do mpls differently for ip4 and ip6
    const SnortConfig* sc = p->context->conf;
    skey.init_vlan(sc, vlan);
    skey.init_address_space(sc, 0);
    skey.init_mpls(sc, 0);
    skey.padding = skey.flags.padding_bits = 0;
    skey.flags.group_used = p->is_inter_group_flow();
    skey.init_groups(p->pkth->ingress_group, p->pkth->egress_group, reversed);

    switch (p->type())
    {
    case PktType::TCP:
        /* Lookup a TCP session */
        ssn = Stream::get_flow(&skey);
        break;
    case PktType::UDP:
        /* Lookup a UDP session */
        ssn = Stream::get_flow(&skey);
        break;
    case PktType::ICMP:
        /* Lookup a ICMP session */
        ssn = Stream::get_flow(&skey);
        break;
    default:
        break;
    }

    if (ssn)
    {
        /* Mark this session as dead. */
        ssn->ssn_state.session_flags |= SSNFLAG_DROP_CLIENT;
        ssn->ssn_state.session_flags |= SSNFLAG_DROP_SERVER;
        ssn->session_state |= STREAM_STATE_UNREACH;
    }

    return 0;
}

//-------------------------------------------------------------------------
// IcmpSession methods
//-------------------------------------------------------------------------

IcmpSession::IcmpSession(Flow* f) : Session(f)
{ }

IcmpSession::~IcmpSession()
{ }

bool IcmpSession::setup(Packet*)
{
    echo_count = 0;
    ssn_time.tv_sec = 0;
    ssn_time.tv_usec = 0;
    flow->ssn_state.session_flags |= SSNFLAG_SEEN_SENDER;
    SESSION_STATS_ADD(icmpStats)

    StreamIcmpConfig* pc = get_icmp_cfg(flow->ssn_server);
    flow->set_default_session_timeout(pc->session_timeout, false);

    return true;
}

void IcmpSession::clear()
{
    IcmpSessionCleanup(flow);
    IcmpHAManager::process_deletion(*flow);
}

int IcmpSession::process(Packet* p)
{
    int status;

    flow->set_expire(p, flow->default_session_timeout);

    if (!(flow->ssn_state.session_flags & SSNFLAG_ESTABLISHED) and !(p->is_from_client()))
    {
        DataBus::publish(Stream::get_pub_id(), StreamEventIds::ICMP_BIDIRECTIONAL, p);
        flow->ssn_state.session_flags |= SSNFLAG_ESTABLISHED;
    }

    switch (p->ptrs.icmph->type)
    {
    case ICMP_DEST_UNREACH:
        status = ProcessIcmpUnreach(p);
        break;

    default:
        /* We only handle the above ICMP messages with stream */
        status = 0;
        break;
    }

    return status;
}

