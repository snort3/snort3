//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

//  portscan.c author Daniel Roelker <droelker@sourcefire.com>
//  ps_detect.cc author Russ Combs <rucombs@cisco.com>

/*
**  - Marc Norton and Jeremy Hewlett were involved in the requirements and
**    design of this portscan detection engine.
**  - Thanks to Judy Novak for her suggestion to log open ports on hosts
**    that are portscanned.  This idea makes portscan a lot more useful for
**    analysts.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ps_detect.h"

#include "hash/xhash.h"
#include "log/messages.h"
#include "protocols/icmp4.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "stream/stream.h"
#include "time/packet_time.h"
#include "utils/cpp_macros.h"
#include "utils/stats.h"

#include "ps_inspect.h"

using namespace snort;

PADDING_GUARD_BEGIN
struct PS_HASH_KEY
{
    int protocol;
    SfIp scanner;
    SfIp scanned;
};
PADDING_GUARD_END

static THREAD_LOCAL XHash* portscan_hash = nullptr;

PS_PKT::PS_PKT(Packet* p)
{
    pkt = p;
    scanner = scanned = nullptr;
    proto = reverse_pkt = 0;
}

PortscanConfig::PortscanConfig()
{
    memset(this, 0, sizeof(*this));
}

PortscanConfig::~PortscanConfig()
{
    if ( ignore_scanners )
        ipset_free(ignore_scanners);

    if ( ignore_scanned )
        ipset_free(ignore_scanned);

    if ( watch_ip )
        ipset_free(watch_ip);
}

/*
**  This function is passed into the hash algorithm, so that
**  we only reuse nodes that aren't priority nodes.  We have to make
**  sure that we only track so many priority nodes, otherwise we could
**  have all priority nodes and not be able to allocate more.
*/
static int ps_tracker_free(void* key, void* data)
{
    if (!key || !data)
        return 0;

    PS_TRACKER* tracker = (PS_TRACKER*)data;

    if (!tracker->priority_node)
        return 0;

    /*
    **  Cycle through the protos to see if it's past the time.
    **  We only get here if we ARE a priority node.
    */
    if (tracker->proto.window >= packet_time())
        return 1;

    return 0;
}

void ps_cleanup()
{
    if ( portscan_hash )
    {
        xhash_delete(portscan_hash);
        portscan_hash = nullptr;
    }
}

unsigned ps_node_size()
{ return sizeof(PS_HASH_KEY) + sizeof(PS_TRACKER); }

void ps_init_hash(unsigned long memcap)
{
    if ( portscan_hash )
        return;

    int rows = memcap / ps_node_size();

    portscan_hash = xhash_new(rows, sizeof(PS_HASH_KEY), sizeof(PS_TRACKER),
        memcap, 1, ps_tracker_free, nullptr, 1);

    if ( !portscan_hash )
        FatalError("Failed to initialize portscan hash table.\n");
}

void ps_reset()
{
    if ( portscan_hash )
        xhash_make_empty(portscan_hash);
}

//  Check scanner and scanned ips to see if we can filter them out.
bool PortScan::ps_ignore_ip(const SfIp* scanner, uint16_t scanner_port,
    const SfIp* scanned, uint16_t scanned_port)
{
    if (config->ignore_scanners)
    {
        if (ipset_contains(config->ignore_scanners, scanner, &scanner_port))
            return true;
    }

    if (config->ignore_scanned)
    {
        if (ipset_contains(config->ignore_scanned, scanned, &scanned_port))
            return true;
    }

    return false;
}

/*
**  Check the incoming packet to decide whether portscan detection cares
**  about this packet.  We try to ignore as many packets as possible.
*/
bool PortScan::ps_filter_ignore(PS_PKT* ps_pkt)
{
    Packet* p;
    int reverse_pkt = 0;
    const SfIp* scanner, * scanned;

    p = (Packet*)ps_pkt->pkt;

    if(!p->ptrs.ip_api.is_ip())
        return true;

    if (p->ptrs.tcph)
    {
        if ( !(config->detect_scans & PS_PROTO_TCP) )
            return true;

        /*
        **  This is where we check all of snort's flags for different
        **  TCP session scenarios.  The checks cover:
        **
        **    - dropping packets in established sessions, but not the
        **      TWH packet.
        **    - dropping the SYN/ACK packet from the server on a valid
        **      connection (we'll catch the TWH later if it happens).
        */
        /*
        **  Ignore packets that are already part of an established TCP
        **  stream.
        */
        if (((p->packet_flags & (PKT_STREAM_EST | PKT_STREAM_TWH))
            == PKT_STREAM_EST) && !(p->ptrs.tcph->th_flags & TH_RST))
        {
            return true;
        }

        /*
        **  Ignore the server's initial response, unless it's to RST
        **  the connection.
        */
        /*
        if(!(p->ptrs.tcph->th_flags & TH_RST) &&
           !(p->packet_flags & (PKT_STREAM_EST)) &&
            (p->is_from_server()))
        {
            return true;
        }
        */
    }
    else if (p->ptrs.udph)
    {
        if ( !(config->detect_scans & PS_PROTO_UDP) )
            return true;
    }
    else if (p->ptrs.icmph)
    {
        if ( p->ptrs.icmph->type != ICMP_DEST_UNREACH and !(config->detect_scans & PS_PROTO_ICMP) )
            return true;
    }
    else
    {
        if ( !(config->detect_scans & PS_PROTO_IP) )
            return true;
    }

    //  Check if the packet is reversed
    if ((p->is_from_server()))
    {
        reverse_pkt = 1;
    }
    else if (p->ptrs.icmph && p->ptrs.icmph->type == ICMP_DEST_UNREACH)
    {
        reverse_pkt = 1;
    }
    else if (p->ptrs.udph and p->flow )
    {
        if (Stream::get_packet_direction(p) & PKT_FROM_SERVER)
            reverse_pkt = 1;
    }

    scanner = p->ptrs.ip_api.get_src();
    scanned = p->ptrs.ip_api.get_dst();

    if (reverse_pkt)
    {
        if (ps_ignore_ip(scanned, p->ptrs.dp, scanner, p->ptrs.sp))
            return true;
    }
    else
    {
        if (ps_ignore_ip(scanner, p->ptrs.sp, scanned, p->ptrs.dp))
            return true;
    }

    ps_pkt->reverse_pkt = reverse_pkt;

    if (config->watch_ip)
    {
        if (ipset_contains(config->watch_ip, scanner, &(p->ptrs.sp)))
            return false;

        if (ipset_contains(config->watch_ip, scanned, &(p->ptrs.dp)))
            return false;

        return true;
    }
    return false;
}

/*
**  Get a tracker node by either finding one or starting a new one.  We may
**  return null, in which case we wait `til the next packet.
*/
static PS_TRACKER* ps_tracker_get(PS_HASH_KEY* key)
{
    PS_TRACKER* ht = (PS_TRACKER*)xhash_find(portscan_hash, (void*)key);

    if ( ht )
        return ht;

    if ( xhash_add(portscan_hash, (void*)key, nullptr) != XHASH_OK )
        return nullptr;

    ht = (PS_TRACKER*)xhash_mru(portscan_hash);

    if ( ht )
        memset(ht, 0x00, sizeof(PS_TRACKER));

    return ht;
}

bool PortScan::ps_tracker_lookup(
    PS_PKT* ps_pkt, PS_TRACKER** scanner, PS_TRACKER** scanned)
{
    PS_HASH_KEY key;
    Packet* p = (Packet*)ps_pkt->pkt;

    if (ps_get_proto(ps_pkt, &key.protocol) == -1)
        return false;

    ps_pkt->proto = key.protocol;

    /*
    **  Let's lookup the host that is being scanned, taking into account
    **  the pkt may be reversed.
    */
    if (config->detect_scan_type &
        (PS_TYPE_PORTSCAN | PS_TYPE_DECOYSCAN | PS_TYPE_DISTPORTSCAN))
    {
        key.scanner.clear();

        if (ps_pkt->reverse_pkt)
            key.scanned.set(*p->ptrs.ip_api.get_src());
        else
            key.scanned.set(*p->ptrs.ip_api.get_dst());

        *scanned = ps_tracker_get(&key);
    }

    //  Let's lookup the host that is scanning.
    if (config->detect_scan_type & PS_TYPE_PORTSWEEP)
    {
        key.scanned.clear();

        if (ps_pkt->reverse_pkt)
            key.scanner.set(*p->ptrs.ip_api.get_dst());
        else
            key.scanner.set(*p->ptrs.ip_api.get_src());

        *scanner = ps_tracker_get(&key);
    }

    return *scanner or *scanned;
}

/*
**  This logic finds the index to the proto array based on the
**  portscan configuration.  We need special logic because the
**  index of the protocol changes based on the configuration.
*/
int PortScan::ps_get_proto(PS_PKT* ps_pkt, int* proto)
{
    Packet* p;

    if (!ps_pkt || !ps_pkt->pkt || !proto)
        return -1;

    p = (Packet*)ps_pkt->pkt;
    *proto = 0;

    if ( config->detect_scans & PS_PROTO_TCP )
    {
        if ((p->ptrs.tcph)
            || ((p->ptrs.icmph) && (p->ptrs.icmph->type == ICMP_DEST_UNREACH)
            && ((p->ptrs.icmph->code == ICMP_PORT_UNREACH)
            || (p->ptrs.icmph->code == ICMP_PKT_FILTERED))
            && (p->proto_bits & PROTO_BIT__TCP_EMBED_ICMP)))
        {
            *proto = PS_PROTO_TCP;
            return 0;
        }
    }

    if ( config->detect_scans & PS_PROTO_UDP )
    {
        if ((p->ptrs.udph)
            || ((p->ptrs.icmph) && (p->ptrs.icmph->type == ICMP_DEST_UNREACH)
            && ((p->ptrs.icmph->code == ICMP_PORT_UNREACH)
            || (p->ptrs.icmph->code == ICMP_PKT_FILTERED))
            && (p->proto_bits & PROTO_BIT__UDP_EMBED_ICMP)))
        {
            *proto = PS_PROTO_UDP;
            return 0;
        }
    }

    if ( config->detect_scans & PS_PROTO_IP )
    {
        if ((p->ptrs.ip_api.is_ip() && (!p->ptrs.icmph))
            || ((p->ptrs.icmph) && (p->ptrs.icmph->type == ICMP_DEST_UNREACH)
            && ((p->ptrs.icmph->code == ICMP_PROT_UNREACH)
            || (p->ptrs.icmph->code == ICMP_PKT_FILTERED))))
        {
            *proto = PS_PROTO_IP;
            return 0;
        }
    }

    if ( config->detect_scans & PS_PROTO_ICMP )
    {
        if (p->ptrs.icmph)
        {
            *proto = PS_PROTO_ICMP;
            return 0;
        }
    }

    return -1;
}

void PortScan::ps_proto_update_window(unsigned interval, PS_PROTO* proto, time_t pkt_time)
{
    if (pkt_time > proto->window)
    {
        memset(proto, 0x00, sizeof(PS_PROTO));

        proto->window = pkt_time + interval;
    }
}

/*
**  This function updates the PS_PROTO structure.
**
**  @param PS_PROTO pointer to structure to update
**  @param int      number to increment portscan counter
**  @param u_long   IP address of other host
**  @param unsigned short  port/ip_proto to track
**  @param time_t   time the packet was received. update windows.
*/
int PortScan::ps_proto_update(PS_PROTO* proto, int ps_cnt, int pri_cnt,
    unsigned window, const SfIp* ip, unsigned short port, time_t pkt_time)
{
    if (!proto)
        return 0;

    /*
    **  If the ps_cnt is negative, that means we are just taking off
    **  for valid connection, and we don't want to do anything else,
    **  like update ip/port, etc.
    */
    if (ps_cnt < 0)
    {
        proto->connection_count += ps_cnt;
        if (proto->connection_count < 0)
            proto->connection_count = 0;

        return 0;
    }

    /*
    **  If we are updating a priority cnt, it means we already did the
    **  unique port and IP on the connection packet.
    **
    **  Priority points are only added for invalid response packets.
    */
    if (pri_cnt)
    {
        proto->priority_count += pri_cnt;
        if (proto->priority_count < 0)
            proto->priority_count = 0;

        return 0;
    }

    /*
    **  Do time check first before we update the counters, so if
    **  we need to reset them we do it before we update them.
    */
    ps_proto_update_window(window, proto, pkt_time);

    //  Update ps counter
    proto->connection_count += ps_cnt;
    if (proto->connection_count < 0)
        proto->connection_count = 0;

    if (!proto->u_ips.equals(*ip, false))
    {
        proto->u_ip_count++;
        proto->u_ips.set(*ip);
    }

    /* we need to do the IP comparisons in host order */

    if (proto->low_ip.is_set())
    {
        if (proto->low_ip.greater_than(*ip))
            proto->low_ip.set(*ip);
    }
    else
    {
        proto->low_ip.set(*ip);
    }

    if (proto->high_ip.is_set())
    {
        if (proto->high_ip.less_than(*ip))
            proto->high_ip.set(*ip);
    }
    else
    {
        proto->high_ip.set(*ip);
    }

    if (proto->u_ports != port)
    {
        proto->u_port_count++;
        proto->u_ports = port;
    }

    if (proto->low_p)
    {
        if (proto->low_p > port)
            proto->low_p = port;
    }
    else
    {
        proto->low_p = port;
    }

    if (proto->high_p)
    {
        if (proto->high_p < port)
            proto->high_p = port;
    }
    else
    {
        proto->high_p = port;
    }

    return 0;
}

static int ps_update_open_ports(PS_PROTO* proto, unsigned short port)
{
    int iCtr;

    for (iCtr = 0; iCtr < proto->open_ports_cnt; iCtr++)
    {
        if (port == proto->open_ports[iCtr])
            return 0;
    }

    if (iCtr < (PS_OPEN_PORTS - 1))
    {
        proto->open_ports[iCtr] = port;
        proto->open_ports_cnt++;
    }

    return 0;
}

/*
**  Determine how to update the portscan counter depending on the type
**  of TCP packet we have.
**
**  We are concerned with three types of TCP packets:
**
**    - initiating TCP packets (we don't care about flags)
**    - TCP 3-way handshake packets (we decrement the counter)
**    - TCP reset packets on unestablished streams.
*/
void PortScan::ps_tracker_update_tcp(PS_PKT* ps_pkt, PS_TRACKER* scanner,
    PS_TRACKER* scanned)
{
    Packet* p = (Packet*)ps_pkt->pkt;
    uint32_t session_flags = 0x0;
    unsigned win = config->tcp_window;

    SfIp cleared;
    cleared.clear();

    /*
    **  Handle the initiating packet.
    **
    **  If this what stream4 considers to be a valid initiator, then
    **  we will use the available stream4 information.  Otherwise, we
    **  can just revert to flow and look for initiators and responders.
    **
    **  For Stream, depending on the configuration, there might not
    **  be a session created only based on the SYN packet.  Stream
    **  by default has code that helps deal with SYN flood attacks,
    **  and may simply ignore the SYN.  In this case, we fall through
    **  to the checks for specific TCP header files (SYN, SYN-ACK, RST).
    **
    **  The "midstream" logic below says that, if we include sessions
    **  picked up midstream, then we don't care about the MIDSTREAM flag.
    **  Otherwise, only consider streams not picked up midstream.
    */
    // FIXIT-H using SSNFLAG_COUNTED_INITIALIZE is a hack to get parity with 2.X
    // this should be completely redone and port_scan should require stream_tcp
    if ( p->flow and (p->flow->ssn_state.session_flags & SSNFLAG_COUNTED_INITIALIZE) )
    {
        session_flags = p->flow->get_session_flags();

        if ((session_flags & SSNFLAG_SEEN_CLIENT) &&
            !(session_flags & SSNFLAG_SEEN_SERVER) &&
            (config->include_midstream || !(session_flags & SSNFLAG_MIDSTREAM)))
        {
            if (scanned)
            {
                ps_proto_update(&scanned->proto, 1, 0, win,
                    p->ptrs.ip_api.get_src(), p->ptrs.dp, packet_time());
            }

            if (scanner)
            {
                ps_proto_update(&scanner->proto, 1, 0, win,
                    p->ptrs.ip_api.get_dst(), p->ptrs.dp, packet_time());
            }
        }
        //  Handle the final packet of the three-way handshake.
        else if (p->packet_flags & PKT_STREAM_TWH)
        {
            if (scanned)
            {
                ps_proto_update(&scanned->proto, -1, 0, win, &cleared, 0, 0);
            }

            if (scanner)
            {
                ps_proto_update(&scanner->proto, -1, 0, win, &cleared, 0, 0);
            }
        }
        //  RST packet on unestablished streams
        else if ((p->is_from_server()) &&
            (p->ptrs.tcph && (p->ptrs.tcph->th_flags & TH_RST)) &&
            (!(p->packet_flags & PKT_STREAM_EST) ||
            (session_flags & SSNFLAG_MIDSTREAM)))
        {
            if (scanned)
            {
                ps_proto_update(&scanned->proto, 0, 1, win, &cleared, 0, 0);
                scanned->priority_node = 1;
            }

            if (scanner)
            {
                ps_proto_update(&scanner->proto, 0, 1, win, &cleared, 0, 0);
                scanner->priority_node = 1;
            }
        }
        /*
        **  We only get here on the server's response to the initial
        **  client connection.
        **
        **  That's why we use the sp, because that's the port that is
        **  open.
        */
        else if ((p->is_from_server()) &&
            !(p->packet_flags & PKT_STREAM_EST))
        {
            if (scanned)
                ps_update_open_ports(&scanned->proto, p->ptrs.sp);
        }
    }
    /*
    ** Stream didn't create a session on the SYN packet,
    ** so check specifically for SYN here.
    */
    else if ( p->ptrs.tcph and p->ptrs.tcph->is_syn_only() )
    {
        /* No session established, packet only has SYN.  SYN only
        ** packet always from client, so use dp.
        */
        if (scanned)
        {
            ps_proto_update(&scanned->proto, 1, 0, win,
                p->ptrs.ip_api.get_src(), p->ptrs.dp, packet_time());
        }

        if (scanner)
        {
            ps_proto_update(&scanner->proto, 1, 0, win,
                p->ptrs.ip_api.get_dst(), p->ptrs.dp, packet_time());
        }
    }
    /*
    ** Stream didn't create a session on the SYN packet,
    ** so check specifically for SYN & ACK here.  Clear based
    ** on the 'completion' of three-way handshake.
    */
    else if ( p->ptrs.tcph and p->ptrs.tcph->is_syn_ack() )
    {
        if (scanned)
        {
            ps_proto_update(&scanned->proto, -1, 0, win, &cleared, 0, 0);
        }

        if (scanner)
        {
            ps_proto_update(&scanner->proto, -1, 0, win, &cleared, 0, 0);
        }
    }
    /*
    ** No session created, clear based on the RST on non
    ** established session.
    */
    else if (p->ptrs.tcph && (p->ptrs.tcph->th_flags & TH_RST))
    {
        if (scanned)
        {
            ps_proto_update(&scanned->proto, 0, 1, win, &cleared, 0, 0);
            scanned->priority_node = 1;
        }

        if (scanner)
        {
            ps_proto_update(&scanner->proto, 0, 1, win, &cleared, 0, 0);
            scanner->priority_node = 1;
        }
    }
    //  If we are an icmp unreachable, deal with it here.
    else if (p->ptrs.icmph)
    {
        if (scanned)
        {
            ps_proto_update(&scanned->proto, 0, 1, win, &cleared, 0, 0);
            scanned->priority_node = 1;
        }

        if (scanner)
        {
            ps_proto_update(&scanner->proto, 0, 1, win, &cleared, 0, 0);
            scanner->priority_node = 1;
        }
    }
}

void PortScan::ps_tracker_update_ip(PS_PKT* ps_pkt, PS_TRACKER* scanner,
    PS_TRACKER* scanned)
{
    Packet* p = (Packet*)ps_pkt->pkt;

    if ( !p->ptrs.ip_api.is_ip() )
        return;

    unsigned win = config->ip_window;
    SfIp cleared;
    cleared.clear();

    if (scanned)
    {
        ps_proto_update(&scanned->proto, 1, 0, win, &cleared, (unsigned short)p->get_ip_proto_next(), 0);
    }

    if (scanner)
    {
        ps_proto_update(&scanner->proto, 1, 0, win, &cleared, (unsigned short)p->get_ip_proto_next(), 0);
    }
}

void PortScan::ps_tracker_update_udp(
    PS_PKT* ps_pkt, PS_TRACKER* scanner, PS_TRACKER* scanned)
{
    Packet* p = (Packet*)ps_pkt->pkt;
    unsigned win = config->udp_window;

    SfIp cleared;
    cleared.clear();

    if (p->ptrs.icmph)
    {
        if (scanned)
        {
            ps_proto_update(&scanned->proto, 0, 1, win, &cleared, 0, 0);
            scanned->priority_node = 1;
        }

        if (scanner)
        {
            ps_proto_update(&scanner->proto, 0, 1, win, &cleared, 0, 0);
            scanner->priority_node = 1;
        }
    }
    else if (p->ptrs.udph)
    {
        if ( p->flow )
        {
            uint32_t direction = Stream::get_packet_direction(p);

            if (direction == PKT_FROM_CLIENT)
            {
                if (scanned)
                {
                    ps_proto_update(&scanned->proto, 1, 0, win,
                        p->ptrs.ip_api.get_src(), p->ptrs.dp, packet_time());
                }

                if (scanner)
                {
                    ps_proto_update(&scanner->proto, 1, 0, win,
                        p->ptrs.ip_api.get_dst(), p->ptrs.dp, packet_time());
                }
            }
            else if (direction == PKT_FROM_SERVER)
            {
                if (scanned)
                    ps_proto_update(&scanned->proto, -1, 0, win, &cleared, 0, 0);

                if (scanner)
                    ps_proto_update(&scanner->proto, -1, 0, win, &cleared, 0, 0);
            }
        }
    }
}

void PortScan::ps_tracker_update_icmp(
    PS_PKT* ps_pkt, PS_TRACKER* scanner, PS_TRACKER*)
{
    Packet* p = (Packet*)ps_pkt->pkt;
    unsigned win = config->icmp_window;

    SfIp cleared;
    cleared.clear();

    if (p->ptrs.icmph)
    {
        switch (p->ptrs.icmph->type)
        {
        case ICMP_ECHO:
        case ICMP_TIMESTAMP:
        case ICMP_ADDRESS:
        case ICMP_INFO_REQUEST:
            ps_proto_update(&scanner->proto, 1, 0, win,
                p->ptrs.ip_api.get_dst(), 0, packet_time());
            break;

        case ICMP_DEST_UNREACH:
            ps_proto_update(&scanner->proto, 0, 1, win, &cleared, 0, 0);
            scanner->priority_node = 1;
            break;

        default:
            break;
        }
    }
}

/*
**  At this point, we should only be looking at transport protocols
**  that we want to.  For instance, if we aren't doing UDP portscans
**  then we won't see UDP packets here because they were ignored.
**
**  This is where we evaluate the packet to add/subtract portscan
**  tracker values and prioritize a tracker.  We also update the
**  time windows.
*/
bool PortScan::ps_tracker_update(PS_PKT* ps_pkt, PS_TRACKER* scanner, PS_TRACKER* scanned)
{
    if ( scanner and scanner->proto.alerts )
        scanner->proto.alerts = PS_ALERT_GENERATED;

    if ( scanned and scanned->proto.alerts )
        scanned->proto.alerts = PS_ALERT_GENERATED;

    switch ( ps_pkt->proto )
    {
    case PS_PROTO_TCP:
        ps_tracker_update_tcp(ps_pkt, scanner, scanned);
        break;

    case PS_PROTO_UDP:
        ps_tracker_update_udp(ps_pkt, scanner, scanned);
        break;

    case PS_PROTO_ICMP:
        ps_tracker_update_icmp(ps_pkt, scanner, scanned);
        break;

    case PS_PROTO_IP:
        ps_tracker_update_ip(ps_pkt, scanner, scanned);
        break;

    default:
        return false;
    }
    return true;
}

static bool ps_alert_one_to_one(
    const PS_ALERT_CONF& conf, PS_PROTO* scanner, PS_PROTO* scanned)
{
    //  Let's evaluate the scanned host.
    if (scanned && !scanned->alerts)
    {
        if (scanned->priority_count >= conf.priority_count)
        {
            if (scanned->u_ip_count < conf.u_ip_count &&
                scanned->u_port_count >= conf.u_port_count)
            {
                if (scanner)
                {
                    if (scanner->priority_count >= conf.priority_count)
                    {
                        //  Now let's check to make sure this is one to one
                        scanned->alerts = PS_ALERT_ONE_TO_ONE;
                        return true;
                    }
                }
                else
                {
                    //  If there is no scanner, then we do the best we can.
                    scanned->alerts = PS_ALERT_ONE_TO_ONE;
                    return true;
                }
            }
        }
        if (scanned->connection_count >= conf.connection_count)
        {
            if (conf.connection_count == 0)
                return false;

            if (scanned->u_ip_count < conf.u_ip_count &&
                scanned->u_port_count >= conf.u_port_count)
            {
                scanned->alerts = PS_ALERT_ONE_TO_ONE_FILTERED;
                return true;
            }
        }
    }

    return false;
}

static bool ps_alert_one_to_one_decoy(
    const PS_ALERT_CONF& conf, PS_PROTO*, PS_PROTO* scanned)
{
    if (scanned && !scanned->alerts)
    {
        if (scanned->priority_count >= conf.priority_count)
        {
            if (scanned->u_ip_count >= conf.u_ip_count &&
                scanned->u_port_count >= conf.u_port_count)
            {
                scanned->alerts = PS_ALERT_ONE_TO_ONE_DECOY;
                return true;
            }
        }
        if (scanned->connection_count >= conf.connection_count)
        {
            if (conf.connection_count == 0)
                return false;

            if (scanned->u_ip_count >= conf.u_ip_count &&
                scanned->u_port_count >= conf.u_port_count)
            {
                scanned->alerts = PS_ALERT_ONE_TO_ONE_DECOY_FILTERED;
                return true;
            }
        }
    }

    return false;
}

static bool ps_alert_many_to_one(
    const PS_ALERT_CONF& conf, PS_PROTO*, PS_PROTO* scanned)
{
    if (scanned && !scanned->alerts)
    {
        if (scanned->priority_count >= conf.priority_count)
        {
            if (scanned->u_ip_count <= conf.u_ip_count &&
                scanned->u_port_count >= conf.u_port_count)
            {
                scanned->alerts = PS_ALERT_DISTRIBUTED;
                return true;
            }
        }
        if (scanned->connection_count >= conf.connection_count)
        {
            if (conf.connection_count == 0)
                return false;

            if (scanned->u_ip_count <= conf.u_ip_count &&
                scanned->u_port_count >= conf.u_port_count)
            {
                scanned->alerts = PS_ALERT_DISTRIBUTED_FILTERED;
                return true;
            }
        }
    }

    return false;
}

static bool ps_alert_one_to_many(
    const PS_ALERT_CONF& conf, PS_PROTO* scanner, PS_PROTO*)
{
    if (scanner && !scanner->alerts)
    {
        if (scanner->priority_count >= conf.priority_count)
        {
            if (scanner->u_ip_count >= conf.u_ip_count &&
                scanner->u_port_count <= conf.u_port_count)
            {
                scanner->alerts = PS_ALERT_PORTSWEEP;
                return true;
            }
        }
        if (scanner->connection_count >= conf.connection_count)
        {
            if (conf.connection_count == 0)
                return false;

            if (scanner->u_ip_count >= conf.u_ip_count &&
                scanner->u_port_count <= conf.u_port_count)
            {
                scanner->alerts = PS_ALERT_PORTSWEEP_FILTERED;
                return true;
            }
        }
    }

    return false;
}

void PortScan::ps_alert_tcp(PS_PROTO* scanner, PS_PROTO* scanned)
{
    if ((config->detect_scan_type & PS_TYPE_PORTSCAN) &&
        ps_alert_one_to_one(config->tcp_ports, scanner, scanned))
    {
        return;
    }

    if ((config->detect_scan_type & PS_TYPE_DECOYSCAN) &&
        ps_alert_one_to_one_decoy(config->tcp_decoy, scanner, scanned))
    {
        return;
    }

    if ((config->detect_scan_type & PS_TYPE_PORTSWEEP) &&
        ps_alert_one_to_many(config->tcp_sweep, scanner, scanned))
    {
        return;
    }

    if ((config->detect_scan_type & PS_TYPE_DISTPORTSCAN) &&
        ps_alert_many_to_one(config->tcp_dist, scanner, scanned))
    {
        return;
    }
}

void PortScan::ps_alert_ip(PS_PROTO* scanner, PS_PROTO* scanned)
{
    if ((config->detect_scan_type & PS_TYPE_PORTSCAN) &&
        ps_alert_one_to_one(config->ip_proto, scanner, scanned))
    {
        return;
    }

    if ((config->detect_scan_type & PS_TYPE_DECOYSCAN) &&
        ps_alert_one_to_one_decoy(config->ip_decoy, scanner, scanned))
    {
        return;
    }

    if ((config->detect_scan_type & PS_TYPE_PORTSWEEP) &&
        ps_alert_one_to_many(config->ip_sweep, scanner, scanned))
    {
        return;
    }

    if ((config->detect_scan_type & PS_TYPE_DISTPORTSCAN) &&
        ps_alert_many_to_one(config->ip_dist, scanner, scanned))
    {
        return;
    }
}

void PortScan::ps_alert_udp(PS_PROTO* scanner, PS_PROTO* scanned)
{
    if ((config->detect_scan_type & PS_TYPE_PORTSCAN) &&
        ps_alert_one_to_one(config->udp_ports, scanner,  scanned))
    {
        return;
    }

    if ((config->detect_scan_type & PS_TYPE_DECOYSCAN) &&
        ps_alert_one_to_one_decoy(config->udp_decoy, scanner, scanned))
    {
        return;
    }

    if ((config->detect_scan_type & PS_TYPE_PORTSWEEP) &&
        ps_alert_one_to_many(config->udp_sweep, scanner, scanned))
    {
        return;
    }

    if ((config->detect_scan_type & PS_TYPE_DISTPORTSCAN) &&
        ps_alert_many_to_one(config->udp_dist, scanner, scanned))
    {
        return;
    }
}

void PortScan::ps_alert_icmp(PS_PROTO* scanner, PS_PROTO* scanned)
{
    if ((config->detect_scan_type & PS_TYPE_PORTSWEEP) &&
        ps_alert_one_to_many(config->icmp_sweep, scanner, scanned))
    {
        return;
    }
}

/*
**  This function evaluates the scanner and scanned trackers and if
**  applicable, generate an alert or alerts for either of the trackers.
**
**  The following alerts can be generated:
**    - One to One Portscan
**    - One to One Decoy Portscan
**    - One to Many Portsweep
**    - Distributed Portscan (Many to One)
**    - Filtered Portscan?
*/
bool PortScan::ps_tracker_alert(
    PS_PKT* ps_pkt, PS_TRACKER* scanner, PS_TRACKER* scanned)
{
    PS_PROTO* scanner_proto = nullptr;
    PS_PROTO* scanned_proto = nullptr;

    if ( scanner )
    {
        if ( config->alert_all )
            scanner->proto.alerts = 0;
        scanner_proto = &scanner->proto;
    }

    if ( scanned )
    {
        if ( config->alert_all )
            scanned->proto.alerts = 0;
        scanned_proto = &scanned->proto;
    }

    switch (ps_pkt->proto)
    {
    case PS_PROTO_TCP:
        ps_alert_tcp(scanner_proto, scanned_proto);
        break;

    case PS_PROTO_UDP:
        ps_alert_udp(scanner_proto, scanned_proto);
        break;

    case PS_PROTO_ICMP:
        ps_alert_icmp(scanner_proto, scanned_proto);
        break;

    case PS_PROTO_IP:
        ps_alert_ip(scanner_proto, scanned_proto);
        break;

    default:
        return false;
    }

    return true;
}

/*
**  The design of portscan is as follows:
**
**    - Filter Packet.  Is the packet part of the ignore or watch list?  Is
**      the packet part of an established TCP session (we ignore it)?
**
**    - Tracker Lookup.  We lookup trackers for src and dst if either is in
**      the watch list, or not in the ignore list if there is no watch list.
**      If there is not tracker, we create a new one and keep track, both of
**      the scanned host and the scanning host.
**
**    - Tracker Update.  We update the tracker using the incoming packet.  If
**      the update causes a portscan alert, then we move into the log alert
**      phase.
**
**    - Tracker Evaluate.  Generate an alert from the updated tracker.  We
**      decide whether we are logging a portscan or sweep (based on the
**      scanning or scanned host, we decide which is more relevant).
*/
int PortScan::ps_detect(PS_PKT* ps_pkt)
{
    PS_TRACKER* scanner = nullptr;
    PS_TRACKER* scanned = nullptr;
    int check_tcp_rst_other_dir = 1;

    assert(ps_pkt and ps_pkt->pkt);

    if (ps_filter_ignore(ps_pkt))
        return 0;

    Packet* p = (Packet*)ps_pkt->pkt;

    do
    {
        if ( !ps_tracker_lookup(ps_pkt, &scanner, &scanned) )
            return 0;

        if ( !ps_tracker_update(ps_pkt, scanner, scanned) )
            return 0;

        if ( !ps_tracker_alert(ps_pkt, scanner, scanned) )
            return 0;

        /* This is added to address the case of no
         * session and a RST packet going back from the Server. */
        if ( p->ptrs.tcph and (p->ptrs.tcph->th_flags & TH_RST) and !p->flow )
        {
            if (ps_pkt->reverse_pkt == 1)
                check_tcp_rst_other_dir = 0;
            else
                ps_pkt->reverse_pkt = 1;
        }
        else
        {
            check_tcp_rst_other_dir = 0;
        }
    }
    while (check_tcp_rst_other_dir);

    ps_pkt->scanner = scanner;
    ps_pkt->scanned = scanned;

    return 1;
}

