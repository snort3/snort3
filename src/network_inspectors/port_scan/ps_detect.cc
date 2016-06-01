//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

/*
**  @file       portscan.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      Detect portscans
**
**  NOTES
**    - Marc Norton and Jeremy Hewlett were involved in the requirements and
**      design of this portscan detection engine.
**    - Thanks to Judy Novak for her suggestion to log open ports
**      on hosts that are portscanned.  This idea makes portscan a lot more
**      useful for analysts.
*/
#include "ps_detect.h"
#include "ps_inspect.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "ipobj.h"
#include "main/snort_config.h"
#include "protocols/packet.h"
#include "time/packet_time.h"
#include "hash/sfxhash.h"
#include "stream/stream_api.h"
#include "sfip/sf_ip.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"
#include "protocols/eth.h"

typedef struct s_PS_HASH_KEY
{
    int protocol;
    sfip_t scanner;
    sfip_t scanned;
} PS_HASH_KEY;

typedef struct s_PS_ALERT_CONF
{
    short connection_count;
    short priority_count;
    short u_ip_count;
    short u_port_count;
} PS_ALERT_CONF;

static THREAD_LOCAL SFXHASH* portscan_hash = NULL;

/*
**  Scanning configurations.  This is where we configure what the thresholds
**  are for the different types of scans, protocols, and sense levels.  If
**  you want to tweak the sense levels, change the values here.
*/
/*
**  TCP alert configurations
*/
static const PS_ALERT_CONF g_tcp_low_ps =       { 0,5,25,5 };
static const PS_ALERT_CONF g_tcp_low_decoy_ps = { 0,15,50,30 };
static const PS_ALERT_CONF g_tcp_low_sweep =    { 0,5,5,15 };
static const PS_ALERT_CONF g_tcp_low_dist_ps =  { 0,15,50,15 };

static const PS_ALERT_CONF g_tcp_med_ps =       { 200,10,60,15 };
static const PS_ALERT_CONF g_tcp_med_decoy_ps = { 200,30,120,60 };
static const PS_ALERT_CONF g_tcp_med_sweep =    { 30,7,7,10 };
static const PS_ALERT_CONF g_tcp_med_dist_ps =  { 200,30,120,30 };

static const PS_ALERT_CONF g_tcp_hi_ps =        { 200,5,100,10 };
static const PS_ALERT_CONF g_tcp_hi_decoy_ps =  { 200,7,200,60 };
static const PS_ALERT_CONF g_tcp_hi_sweep =     { 30,3,3,10 };
static const PS_ALERT_CONF g_tcp_hi_dist_ps =   { 200,5,200,10 };

/*
**  UDP alert configurations
*/
static const PS_ALERT_CONF g_udp_low_ps =       { 0,5,25,5 };
static const PS_ALERT_CONF g_udp_low_decoy_ps = { 0,15,50,30 };
static const PS_ALERT_CONF g_udp_low_sweep =    { 0,5,5,15 };
static const PS_ALERT_CONF g_udp_low_dist_ps =  { 0,15,50,15 };

static const PS_ALERT_CONF g_udp_med_ps =       { 200,10,60,15 };
static const PS_ALERT_CONF g_udp_med_decoy_ps = { 200,30,120,60 };
static const PS_ALERT_CONF g_udp_med_sweep =    { 30,5,5,20 };
static const PS_ALERT_CONF g_udp_med_dist_ps =  { 200,30,120,30 };

static const PS_ALERT_CONF g_udp_hi_ps =        { 200,3,100,10 };
static const PS_ALERT_CONF g_udp_hi_decoy_ps =  { 200,7,200,60 };
static const PS_ALERT_CONF g_udp_hi_sweep =     { 30,3,3,10 };
static const PS_ALERT_CONF g_udp_hi_dist_ps =   { 200,3,200,10 };

/*
**  IP Protocol alert configurations
*/
static const PS_ALERT_CONF g_ip_low_ps =        { 0,10,10,50 };
static const PS_ALERT_CONF g_ip_low_decoy_ps =  { 0,40,50,25 };
static const PS_ALERT_CONF g_ip_low_sweep =     { 0,10,10,10 };
static const PS_ALERT_CONF g_ip_low_dist_ps =   { 0,15,25,50 };

static const PS_ALERT_CONF g_ip_med_ps =        { 200,10,10,50 };
static const PS_ALERT_CONF g_ip_med_decoy_ps =  { 200,40,50,25 };
static const PS_ALERT_CONF g_ip_med_sweep =     { 30,10,10,10 };
static const PS_ALERT_CONF g_ip_med_dist_ps =   { 200,15,25,50 };

static const PS_ALERT_CONF g_ip_hi_ps =         { 200,3,3,10 };
static const PS_ALERT_CONF g_ip_hi_decoy_ps =   { 200,7,15,5 };
static const PS_ALERT_CONF g_ip_hi_sweep =      { 30,3,3,7 };
static const PS_ALERT_CONF g_ip_hi_dist_ps =    { 200,3,11,10 };

/*
**  ICMP alert configurations
*/
static const PS_ALERT_CONF g_icmp_low_sweep =   { 0,5,5,5 };
static const PS_ALERT_CONF g_icmp_med_sweep =   { 20,5,5,5 };
static const PS_ALERT_CONF g_icmp_hi_sweep =    { 10,3,3,5 };

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
**  NAME
**    ps_tracker_free::
*/
/**
**  This function is passed into the hash algorithm, so that
**  we only reuse nodes that aren't priority nodes.  We have to make
**  sure that we only track so many priority nodes, otherwise we could
**  have all priority nodes and not be able to allocate more.
*/
static int ps_tracker_free(void* key, void* data)
{
    PS_TRACKER* tracker;

    if (!key || !data)
        return 0;

    tracker = (PS_TRACKER*)data;
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
    if (portscan_hash != NULL)
    {
        sfxhash_delete(portscan_hash);
        portscan_hash = NULL;
    }
}

void ps_init_hash(unsigned long memcap)
{
    if ( portscan_hash )
        return;

    int rows = 0;
    int factor = 0;
#if SIZEOF_LONG_INT == 8
    factor = 125;
#else
    factor = 250;
#endif

    rows = memcap/factor;

    portscan_hash = sfxhash_new(rows, sizeof(PS_HASH_KEY), sizeof(PS_TRACKER),
        memcap, 1, ps_tracker_free, NULL, 1);

    if (portscan_hash == NULL)
        FatalError("Failed to initialize portscan hash table.\n");
}

/*
**  NAME
**    ps_reset::
*/
/**
**  Reset the portscan infrastructure.
*/
void ps_reset()
{
    if (portscan_hash != NULL)
        sfxhash_make_empty(portscan_hash);
}

/*
**  NAME
**    ps_ignore_ip::
*/
/**
**  Check scanner and scanned ips to see if we can filter them out.
*/
int PortScan::ps_ignore_ip(const sfip_t* scanner, uint16_t scanner_port,
    const sfip_t* scanned, uint16_t scanned_port)
{
    if (config->ignore_scanners)
    {
        if (ipset_contains(config->ignore_scanners, scanner, &scanner_port))
            return 1;
    }

    if (config->ignore_scanned)
    {
        if (ipset_contains(config->ignore_scanned, scanned, &scanned_port))
            return 1;
    }

    return 0;
}

/*
**  NAME
**    ps_filter_ignore::
*/
/**
**  Check the incoming packet to decide whether portscan detection cares
**  about this packet.  We try to ignore as many packets as possible.
*/
int PortScan::ps_filter_ignore(PS_PKT* ps_pkt)
{
    Packet* p;
    int reverse_pkt = 0;
    const sfip_t* scanner, * scanned;

    p = (Packet*)ps_pkt->pkt;

    if(!p->ptrs.ip_api.is_ip())
        return 1;

    if (p->ptrs.tcph)
    {
        if (!(config->detect_scans & PS_PROTO_TCP))
            return 1;

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
            return 1;
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
            return 1;
        }
        */
    }
    else if (p->ptrs.udph)
    {
        if (!(config->detect_scans & PS_PROTO_UDP))
            return 1;
    }
    else if (p->ptrs.icmph)
    {
        if (p->ptrs.icmph->type != ICMP_DEST_UNREACH &&
            !(config->detect_scans & PS_PROTO_ICMP))
        {
            return 1;
        }
    }
    else
    {
        if (!(config->detect_scans & PS_PROTO_IP))
            return 1;
    }

    /*
    **  Check if the packet is reversed
    */
    if ((p->is_from_server()))
    {
        reverse_pkt = 1;
    }
    else if (p->ptrs.icmph && p->ptrs.icmph->type == ICMP_DEST_UNREACH)
    {
        reverse_pkt = 1;
    }
    else if (p->ptrs.udph && p->flow)
    {
        if (stream.get_packet_direction(p) & PKT_FROM_SERVER)
            reverse_pkt = 1;
    }

    scanner = p->ptrs.ip_api.get_src();
    scanned = p->ptrs.ip_api.get_dst();

    if (reverse_pkt)
    {
        if (ps_ignore_ip(scanned, p->ptrs.dp, scanner, p->ptrs.sp))
            return 1;
    }
    else
    {
        if (ps_ignore_ip(scanner, p->ptrs.sp, scanned, p->ptrs.dp))
            return 1;
    }

    ps_pkt->reverse_pkt = reverse_pkt;

    if (config->watch_ip)
    {
        if (ipset_contains(config->watch_ip, scanner, &(p->ptrs.sp)))
            return 0;
        if (ipset_contains(config->watch_ip, scanned, &(p->ptrs.dp)))
            return 0;

        return 1;
    }
    return 0;
}

/*
**  NAME
**    ps_tracker_init::
*/
/**
**  Right now all we do is memset, but just in case we want to do more
**  initialization has been extracted.
*/
static int ps_tracker_init(PS_TRACKER* tracker)
{
    memset(tracker, 0x00, sizeof(PS_TRACKER));

    return 0;
}

/*
**  NAME
**    ps_tracker_get::
*/
/**
**  Get a tracker node by either finding one or starting a new one.  We may
**  return NULL, in which case we wait till the next packet.
*/
static int ps_tracker_get(PS_TRACKER** ht, PS_HASH_KEY* key)
{
    int iRet;

    *ht = (PS_TRACKER*)sfxhash_find(portscan_hash, (void*)key);
    if (!(*ht))
    {
        iRet = sfxhash_add(portscan_hash, (void*)key, NULL);
        if (iRet == SFXHASH_OK)
        {
            *ht = (PS_TRACKER*)sfxhash_mru(portscan_hash);
            if (!(*ht))
                return -1;

            ps_tracker_init(*ht);
        }
        else
        {
            return -1;
        }
    }

    return 0;
}

int PortScan::ps_tracker_lookup(PS_PKT* ps_pkt, PS_TRACKER** scanner,
    PS_TRACKER** scanned)
{
    PS_HASH_KEY key;
    Packet* p;

    if (ps_pkt->pkt == NULL)
        return -1;

    p = (Packet*)ps_pkt->pkt;

    if (ps_get_proto(ps_pkt, &key.protocol) == -1)
        return -1;

    ps_pkt->proto = key.protocol;

    /*
    **  Let's lookup the host that is being scanned, taking into account
    **  the pkt may be reversed.
    */
    if (config->detect_scan_type &
        (PS_TYPE_PORTSCAN | PS_TYPE_DECOYSCAN | PS_TYPE_DISTPORTSCAN))
    {
        sfip_clear(key.scanner);

        if (ps_pkt->reverse_pkt)
            sfip_copy(key.scanned, p->ptrs.ip_api.get_src());
        else
            sfip_copy(key.scanned, p->ptrs.ip_api.get_dst());

        /*
        **  Get the scanned tracker.
        */
        ps_tracker_get(scanned, &key);
    }

    /*
    **  Let's lookup the host that is scanning.
    */
    if (config->detect_scan_type & PS_TYPE_PORTSWEEP)
    {
        sfip_clear(key.scanned);

        if (ps_pkt->reverse_pkt)
            sfip_copy(key.scanner, p->ptrs.ip_api.get_dst());
        else
            sfip_copy(key.scanner, p->ptrs.ip_api.get_src());

        /*
        **  Get the scanner tracker
        */
        ps_tracker_get(scanner, &key);
    }

    if ((*scanner == NULL) && (*scanned == NULL))
        return -1;

    return 0;
}

/*
**  NAME
**    ps_get_proto_index::
*/
/**
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

    if (config->detect_scans & PS_PROTO_TCP)
    {
        if ((p->ptrs.tcph != NULL)
            || ((p->ptrs.icmph != NULL) && (p->ptrs.icmph->type == ICMP_DEST_UNREACH)
            && ((p->ptrs.icmph->code == ICMP_PORT_UNREACH)
            || (p->ptrs.icmph->code == ICMP_PKT_FILTERED))
            && (p->proto_bits & PROTO_BIT__TCP_EMBED_ICMP)))
        {
            *proto = PS_PROTO_TCP;
            return 0;
        }
    }

    if (config->detect_scans & PS_PROTO_UDP)
    {
        if ((p->ptrs.udph != NULL)
            || ((p->ptrs.icmph != NULL) && (p->ptrs.icmph->type == ICMP_DEST_UNREACH)
            && ((p->ptrs.icmph->code == ICMP_PORT_UNREACH)
            || (p->ptrs.icmph->code == ICMP_PKT_FILTERED))
            && (p->proto_bits & PROTO_BIT__UDP_EMBED_ICMP)))
        {
            *proto = PS_PROTO_UDP;
            return 0;
        }
    }

    if (config->detect_scans & PS_PROTO_IP)
    {
        if ((p->ptrs.ip_api.is_ip() && (p->ptrs.icmph == NULL))
                || ((p->ptrs.icmph != NULL) && (p->ptrs.icmph->type == ICMP_DEST_UNREACH)
                    && ((p->ptrs.icmph->code == ICMP_PROT_UNREACH)
                        || (p->ptrs.icmph->code == ICMP_PKT_FILTERED))))
        {
            *proto = PS_PROTO_IP;
            return 0;
        }
    }

    if (config->detect_scans & PS_PROTO_ICMP)
    {
        if (p->ptrs.icmph != NULL)
        {
            *proto = PS_PROTO_ICMP;
            return 0;
        }
    }

    return -1;
}

/*
**  NAME
**    ps_proto_update_window::
*/
/**
**  Update the proto time windows based on the portscan sensitivity
**  level.
*/
int PortScan::ps_proto_update_window(PS_PROTO* proto, time_t pkt_time)
{
    time_t interval;

    switch (config->sense_level)
    {
    case PS_SENSE_LOW:
        //interval = 15;
        interval = 60;
        break;

    case PS_SENSE_MEDIUM:
        //interval = 15;
        interval = 90;
        break;

    case PS_SENSE_HIGH:
        interval = 600;
        break;

    default:
        return -1;
    }

    /*
    **  If we are outside of the window, reset our ps counters.
    */
    if (pkt_time > proto->window)
    {
        memset(proto, 0x00, sizeof(PS_PROTO));

        proto->window = pkt_time + interval;

        return 0;
    }

    return 0;
}

/*
**  NAME
**    ps_proto_update::
*/
/**
**  This function updates the PS_PROTO structure.
**
**  @param PS_PROTO pointer to structure to update
**  @param int      number to increment portscan counter
**  @param u_long   IP address of other host
**  @param u_short  port/ip_proto to track
**  @param time_t   time the packet was received. update windows.
*/
int PortScan::ps_proto_update(PS_PROTO* proto, int ps_cnt, int pri_cnt, const sfip_t* ip,
    u_short port, time_t pkt_time)
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
    if (ps_proto_update_window(proto, pkt_time))
        return -1;

    /*
    **  Update ps counter
    */
    proto->connection_count += ps_cnt;
    if (proto->connection_count < 0)
        proto->connection_count = 0;

    if (!sfip_unset_equals(&proto->u_ips, ip))
    {
        proto->u_ip_count++;
        sfip_copy(proto->u_ips, ip);
    }

    /* we need to do the IP comparisons in host order */

    if (sfip_is_set(&proto->low_ip))
    {
        if (sfip_greater(&proto->low_ip, ip))
            sfip_copy(proto->low_ip, ip);
    }
    else
    {
        sfip_copy(proto->low_ip, ip);
    }

    if (sfip_is_set(proto->high_ip))
    {
        if (sfip_lesser(&proto->high_ip, ip))
            sfip_copy(proto->high_ip, ip);
    }
    else
    {
        sfip_copy(proto->high_ip, ip);
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

        if (proto->alerts == PS_ALERT_GENERATED)
        {
            proto->alerts = PS_ALERT_OPEN_PORT;
        }
    }

    return 0;
}

/*
**  NAME
**    ps_tracker_update_tcp::
*/
/**
**  Determine how to update the portscan counter depending on the type
**  of TCP packet we have.
**
**  We are concerned with three types of TCP packets:
**
**    - initiating TCP packets (we don't care about flags)
**    - TCP 3-way handshake packets (we decrement the counter)
**    - TCP reset packets on unestablished streams.
*/
int PortScan::ps_tracker_update_tcp(PS_PKT* ps_pkt, PS_TRACKER* scanner,
    PS_TRACKER* scanned)
{
    Packet* p;
    uint32_t session_flags = 0x0;
    sfip_t cleared;
    sfip_clear(cleared);

    p = (Packet*)ps_pkt->pkt;

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
    if ( p->flow )
        session_flags = p->flow->get_session_flags();

    if ( session_flags & (SSNFLAG_SEEN_CLIENT|SSNFLAG_SEEN_SERVER) )
    {
        if ((session_flags & SSNFLAG_SEEN_CLIENT) &&
            !(session_flags & SSNFLAG_SEEN_SERVER) &&
            (config->include_midstream || !(session_flags & SSNFLAG_MIDSTREAM)))
        {
            if (scanned)
            {
                ps_proto_update(&scanned->proto,1,0,
                    p->ptrs.ip_api.get_src(),p->ptrs.dp, packet_time());
            }

            if (scanner)
            {
                ps_proto_update(&scanner->proto,1,0,
                    p->ptrs.ip_api.get_dst(),p->ptrs.dp, packet_time());
            }
        }
        /*
        **  Handle the final packet of the three-way handshake.
        */
        else if (p->packet_flags & PKT_STREAM_TWH)
        {
            if (scanned)
            {
                ps_proto_update(&scanned->proto,-1,0,&cleared,0,0);
            }

            if (scanner)
            {
                ps_proto_update(&scanner->proto,-1,0,&cleared,0,0);
            }
        }
        /*
        **  RST packet on unestablished streams
        */
        else if ((p->is_from_server()) &&
            (p->ptrs.tcph && (p->ptrs.tcph->th_flags & TH_RST)) &&
            (!(p->packet_flags & PKT_STREAM_EST) ||
            (session_flags & SSNFLAG_MIDSTREAM)))
        {
            if (scanned)
            {
                ps_proto_update(&scanned->proto,0,1,&cleared,0,0);
                scanned->priority_node = 1;
            }

            if (scanner)
            {
                ps_proto_update(&scanner->proto,0,1,&cleared,0,0);
                scanner->priority_node = 1;
            }
        }
        /*
        **  We only get here on the server's response to the intial
        **  client connection.
        **
        **  That's why we use the sp, because that's the port that is
        **  open.
        */
        else if ((p->is_from_server()) &&
            !(p->packet_flags & PKT_STREAM_EST))
        {
            if (scanned)
            {
                ps_update_open_ports(&scanned->proto, p->ptrs.sp);
            }

            if (scanner)
            {
                if (scanner->proto.alerts == PS_ALERT_GENERATED)
                    scanner->proto.alerts = PS_ALERT_OPEN_PORT;
            }
        }
    }
    /*
    ** Stream didn't create a session on the SYN packet,
    ** so check specifically for SYN here.
    */
    else if (p->ptrs.tcph && (p->ptrs.tcph->th_flags == TH_SYN))
    {
        /* No session established, packet only has SYN.  SYN only
        ** packet always from client, so use dp.
        */
        if (scanned)
        {
            ps_proto_update(&scanned->proto,1,0,
                p->ptrs.ip_api.get_src(),p->ptrs.dp, packet_time());
        }

        if (scanner)
        {
            ps_proto_update(&scanner->proto,1,0,
                p->ptrs.ip_api.get_dst(),p->ptrs.dp, packet_time());
        }
    }
    /*
    ** Stream didn't create a session on the SYN packet,
    ** so check specifically for SYN & ACK here.  Clear based
    ** on the 'completion' of three-way handshake.
    */
    else if (p->ptrs.tcph && (p->ptrs.tcph->th_flags == (TH_SYN|TH_ACK)))
    {
        if (scanned)
        {
            ps_proto_update(&scanned->proto,-1,0,&cleared,0,0);
        }

        if (scanner)
        {
            ps_proto_update(&scanner->proto,-1,0,&cleared,0,0);
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
            ps_proto_update(&scanned->proto,0,1,&cleared,0,0);
            scanned->priority_node = 1;
        }

        if (scanner)
        {
            ps_proto_update(&scanner->proto,0,1,&cleared,0,0);
            scanner->priority_node = 1;
        }
    }
    /*
    **  If we are an icmp unreachable, deal with it here.
    */
    else if (p->ptrs.icmph)
    {
        if (scanned)
        {
            ps_proto_update(&scanned->proto,0,1,&cleared,0,0);
            scanned->priority_node = 1;
        }

        if (scanner)
        {
            ps_proto_update(&scanner->proto,0,1,&cleared,0,0);
            scanner->priority_node = 1;
        }
    }
    return 0;
}

int PortScan::ps_tracker_update_ip(PS_PKT* ps_pkt, PS_TRACKER* scanner,
    PS_TRACKER* scanned)
{
    Packet* p;
    sfip_t cleared;
    sfip_clear(cleared);

    p = (Packet*)ps_pkt->pkt;

    if(p->ptrs.ip_api.is_ip())
    {
        if (p->ptrs.icmph)
        {
            if (scanned)
            {
                ps_proto_update(&scanned->proto,0,1,&cleared,0,0);
                scanned->priority_node = 1;
            }

            if (scanner)
            {
                ps_proto_update(&scanner->proto,0,1,&cleared,0,0);
                scanner->priority_node = 1;
            }

            return 0;
        }
    }

    return 0;
}

int PortScan::ps_tracker_update_udp(PS_PKT* ps_pkt, PS_TRACKER* scanner,
    PS_TRACKER* scanned)
{
    Packet* p;
    sfip_t cleared;
    sfip_clear(cleared);

    p = (Packet*)ps_pkt->pkt;

    if (p->ptrs.icmph)
    {
        if (scanned)
        {
            ps_proto_update(&scanned->proto,0,1,&cleared,0,0);
            scanned->priority_node = 1;
        }

        if (scanner)
        {
            ps_proto_update(&scanner->proto,0,1,&cleared,0,0);
            scanner->priority_node = 1;
        }
    }
    else if (p->ptrs.udph)
    {
        if ( p->flow )
        {
            uint32_t direction = stream.get_packet_direction(p);

            if (direction == PKT_FROM_CLIENT)
            {
                if (scanned)
                {
                    ps_proto_update(&scanned->proto,1,0,
                        p->ptrs.ip_api.get_src(),p->ptrs.dp, packet_time());
                }

                if (scanner)
                {
                    ps_proto_update(&scanner->proto,1,0,
                        p->ptrs.ip_api.get_dst(),p->ptrs.dp, packet_time());
                }
            }
            else if (direction == PKT_FROM_SERVER)
            {
                if (scanned)
                    ps_proto_update(&scanned->proto,-1,0,&cleared,0,0);

                if (scanner)
                    ps_proto_update(&scanner->proto,-1,0,&cleared,0,0);
            }
        }
    }

    return 0;
}

int PortScan::ps_tracker_update_icmp(
    PS_PKT* ps_pkt, PS_TRACKER* scanner, PS_TRACKER*)
{
    Packet* p;
    sfip_t cleared;
    sfip_clear(cleared);

    p = (Packet*)ps_pkt->pkt;

    if (p->ptrs.icmph)
    {
        switch (p->ptrs.icmph->type)
        {
        case ICMP_ECHO:
        case ICMP_TIMESTAMP:
        case ICMP_ADDRESS:
        case ICMP_INFO_REQUEST:

            if (scanner)
            {
                ps_proto_update(&scanner->proto,1,0,
                    p->ptrs.ip_api.get_dst(), 0, packet_time());
            }

            break;

        case ICMP_DEST_UNREACH:

            if (scanner)
            {
                ps_proto_update(&scanner->proto,0,1,&cleared,0,0);
                scanner->priority_node = 1;
            }

            break;

        default:
            break;
        }
    }

    return 0;
}

/*
**  NAME
**    ps_tracker_update::
*/
/**
**  At this point, we should only be looking at tranport protocols
**  that we want to.  For instance, if we aren't doing UDP portscans
**  then we won't see UDP packets here because they were ignored.
**
**  This is where we evaluate the packet to add/subtract portscan
**  tracker values and prioritize a tracker.  We also update the
**  time windows.
*/
int PortScan::ps_tracker_update(PS_PKT* ps_pkt, PS_TRACKER* scanner,
    PS_TRACKER* scanned)
{
    if (scanner && scanner->proto.alerts)
        scanner->proto.alerts = PS_ALERT_GENERATED;

    if (scanned && scanned->proto.alerts)
        scanned->proto.alerts = PS_ALERT_GENERATED;

    switch (ps_pkt->proto)
    {
    case PS_PROTO_TCP:
        if (ps_tracker_update_tcp(ps_pkt, scanner, scanned))
            return -1;

        break;

    case PS_PROTO_UDP:
        if (ps_tracker_update_udp(ps_pkt, scanner, scanned))
            return -1;

        break;

    case PS_PROTO_ICMP:
        if (ps_tracker_update_icmp(ps_pkt, scanner, scanned))
            return -1;

        break;

    case PS_PROTO_IP:
        if (ps_tracker_update_ip(ps_pkt, scanner, scanned))
            return -1;

        break;

    default:
        return -1;
    }

    return 0;
}

static int ps_alert_one_to_one(PS_PROTO* scanner, PS_PROTO* scanned,
    const PS_ALERT_CONF* conf)
{
    if (!conf)
        return -1;

    /*
    **  Let's evaluate the scanned host.
    */
    if (scanned && !scanned->alerts)
    {
        if (scanned->priority_count >= conf->priority_count)
        {
            if (scanned->u_ip_count < conf->u_ip_count &&
                scanned->u_port_count >= conf->u_port_count)
            {
                if (scanner)
                {
                    if (scanner->priority_count >= conf->priority_count)
                    {
                        /*
                        **  Now let's check to make sure this is one
                        **  to one
                        */
                        scanned->alerts = PS_ALERT_ONE_TO_ONE;
                        return 0;
                    }
                }
                else
                {
                    /*
                    **  If there is no scanner, then we do the best we can.
                    */
                    scanned->alerts = PS_ALERT_ONE_TO_ONE;
                    return 0;
                }
            }
        }
        if (scanned->connection_count >= conf->connection_count)
        {
            if (conf->connection_count == 0)
                return 0;

            if (scanned->u_ip_count < conf->u_ip_count &&
                scanned->u_port_count >= conf->u_port_count)
            {
                scanned->alerts = PS_ALERT_ONE_TO_ONE_FILTERED;
                return 0;
            }
        }
    }

    return 0;
}

static int ps_alert_one_to_one_decoy(
    PS_PROTO*, PS_PROTO* scanned, const PS_ALERT_CONF* conf)
{
    if (!conf)
        return -1;

    if (scanned && !scanned->alerts)
    {
        if (scanned->priority_count >= conf->priority_count)
        {
            if (scanned->u_ip_count >= conf->u_ip_count &&
                scanned->u_port_count >= conf->u_port_count)
            {
                scanned->alerts = PS_ALERT_ONE_TO_ONE_DECOY;
                return 0;
            }
        }
        if (scanned->connection_count >= conf->connection_count)
        {
            if (conf->connection_count == 0)
                return 0;

            if (scanned->u_ip_count >= conf->u_ip_count &&
                scanned->u_port_count >= conf->u_port_count)
            {
                scanned->alerts = PS_ALERT_ONE_TO_ONE_DECOY_FILTERED;
                return 0;
            }
        }
    }

    return 0;
}

static int ps_alert_many_to_one(
    PS_PROTO*, PS_PROTO* scanned, const PS_ALERT_CONF* conf)
{
    if (!conf)
        return -1;

    if (scanned && !scanned->alerts)
    {
        if (scanned->priority_count >= conf->priority_count)
        {
            if (scanned->u_ip_count <= conf->u_ip_count &&
                scanned->u_port_count >= conf->u_port_count)
            {
                scanned->alerts = PS_ALERT_DISTRIBUTED;
                return 0;
            }
        }
        if (scanned->connection_count >= conf->connection_count)
        {
            if (conf->connection_count == 0)
                return 0;

            if (scanned->u_ip_count <= conf->u_ip_count &&
                scanned->u_port_count >= conf->u_port_count)
            {
                scanned->alerts = PS_ALERT_DISTRIBUTED_FILTERED;
                return 0;
            }
        }
    }

    return 0;
}

static int ps_alert_one_to_many(
    PS_PROTO* scanner, PS_PROTO*, const PS_ALERT_CONF* conf)
{
    if (!conf)
        return -1;

    if (scanner && !scanner->alerts)
    {
        if (scanner->priority_count >= conf->priority_count)
        {
            if (scanner->u_ip_count >= conf->u_ip_count &&
                scanner->u_port_count <= conf->u_port_count)
            {
                scanner->alerts = PS_ALERT_PORTSWEEP;
                return 1;
            }
        }
        if (scanner->connection_count >= conf->connection_count)
        {
            if (conf->connection_count == 0)
                return 0;

            if (scanner->u_ip_count >= conf->u_ip_count &&
                scanner->u_port_count <= conf->u_port_count)
            {
                scanner->alerts = PS_ALERT_PORTSWEEP_FILTERED;
                return 1;
            }
        }
    }

    return 0;
}

int PortScan::ps_alert_tcp(PS_PROTO* scanner, PS_PROTO* scanned)
{
    static THREAD_LOCAL const PS_ALERT_CONF* one_to_one;
    static THREAD_LOCAL const PS_ALERT_CONF* one_to_one_decoy;
    static THREAD_LOCAL const PS_ALERT_CONF* one_to_many;
    static THREAD_LOCAL const PS_ALERT_CONF* many_to_one;

    /*
    ** Set the configurations depending on the sensitivity
    ** level.
    */
    switch (config->sense_level)
    {
    case PS_SENSE_HIGH:
        one_to_one       = &g_tcp_hi_ps;
        one_to_one_decoy = &g_tcp_hi_decoy_ps;
        one_to_many      = &g_tcp_hi_sweep;
        many_to_one      = &g_tcp_hi_dist_ps;

        break;

    case PS_SENSE_MEDIUM:
        one_to_one       = &g_tcp_med_ps;
        one_to_one_decoy = &g_tcp_med_decoy_ps;
        one_to_many      = &g_tcp_med_sweep;
        many_to_one      = &g_tcp_med_dist_ps;

        break;

    case PS_SENSE_LOW:
        one_to_one       = &g_tcp_low_ps;
        one_to_one_decoy = &g_tcp_low_decoy_ps;
        one_to_many      = &g_tcp_low_sweep;
        many_to_one      = &g_tcp_low_dist_ps;

        break;

    default:
        return -1;
    }

    /*
    **  Do detection on the different portscan types.
    */
    if ((config->detect_scan_type & PS_TYPE_PORTSCAN) &&
        ps_alert_one_to_one(scanner, scanned, one_to_one))
    {
        return 0;
    }

    if ((config->detect_scan_type & PS_TYPE_DECOYSCAN) &&
        ps_alert_one_to_one_decoy(scanner, scanned, one_to_one_decoy))
    {
        return 0;
    }

    if ((config->detect_scan_type & PS_TYPE_PORTSWEEP) &&
        ps_alert_one_to_many(scanner, scanned, one_to_many))
    {
        return 0;
    }

    if ((config->detect_scan_type & PS_TYPE_DISTPORTSCAN) &&
        ps_alert_many_to_one(scanner, scanned, many_to_one))
    {
        return 0;
    }

    return 0;
}

int PortScan::ps_alert_ip(PS_PROTO* scanner, PS_PROTO* scanned)
{
    static THREAD_LOCAL const PS_ALERT_CONF* one_to_one;
    static THREAD_LOCAL const PS_ALERT_CONF* one_to_one_decoy;
    static THREAD_LOCAL const PS_ALERT_CONF* one_to_many;
    static THREAD_LOCAL const PS_ALERT_CONF* many_to_one;

    /*
    ** Set the configurations depending on the sensitivity
    ** level.
    */
    switch (config->sense_level)
    {
    case PS_SENSE_HIGH:
        one_to_one       = &g_ip_hi_ps;
        one_to_one_decoy = &g_ip_hi_decoy_ps;
        one_to_many      = &g_ip_hi_sweep;
        many_to_one      = &g_ip_hi_dist_ps;

        break;

    case PS_SENSE_MEDIUM:
        one_to_one       = &g_ip_med_ps;
        one_to_one_decoy = &g_ip_med_decoy_ps;
        one_to_many      = &g_ip_med_sweep;
        many_to_one      = &g_ip_med_dist_ps;

        break;

    case PS_SENSE_LOW:
        one_to_one       = &g_ip_low_ps;
        one_to_one_decoy = &g_ip_low_decoy_ps;
        one_to_many      = &g_ip_low_sweep;
        many_to_one      = &g_ip_low_dist_ps;

        break;

    default:
        return -1;
    }

    /*
    **  Do detection on the different portscan types.
    */
    if ((config->detect_scan_type & PS_TYPE_PORTSCAN) &&
        ps_alert_one_to_one(scanner, scanned, one_to_one))
    {
        return 0;
    }

    if ((config->detect_scan_type & PS_TYPE_DECOYSCAN) &&
        ps_alert_one_to_one_decoy(scanner, scanned, one_to_one_decoy))
    {
        return 0;
    }

    if ((config->detect_scan_type & PS_TYPE_PORTSWEEP) &&
        ps_alert_one_to_many(scanner, scanned, one_to_many))
    {
        return 0;
    }

    if ((config->detect_scan_type & PS_TYPE_DISTPORTSCAN) &&
        ps_alert_many_to_one(scanner, scanned, many_to_one))
    {
        return 0;
    }

    return 0;
}

int PortScan::ps_alert_udp(PS_PROTO* scanner, PS_PROTO* scanned)
{
    static THREAD_LOCAL const PS_ALERT_CONF* one_to_one;
    static THREAD_LOCAL const PS_ALERT_CONF* one_to_one_decoy;
    static THREAD_LOCAL const PS_ALERT_CONF* one_to_many;
    static THREAD_LOCAL const PS_ALERT_CONF* many_to_one;

    /*
    ** Set the configurations depending on the sensitivity
    ** level.
    */
    switch (config->sense_level)
    {
    case PS_SENSE_HIGH:
        one_to_one       = &g_udp_hi_ps;
        one_to_one_decoy = &g_udp_hi_decoy_ps;
        one_to_many      = &g_udp_hi_sweep;
        many_to_one      = &g_udp_hi_dist_ps;

        break;

    case PS_SENSE_MEDIUM:
        one_to_one       = &g_udp_med_ps;
        one_to_one_decoy = &g_udp_med_decoy_ps;
        one_to_many      = &g_udp_med_sweep;
        many_to_one      = &g_udp_med_dist_ps;

        break;

    case PS_SENSE_LOW:
        one_to_one       = &g_udp_low_ps;
        one_to_one_decoy = &g_udp_low_decoy_ps;
        one_to_many      = &g_udp_low_sweep;
        many_to_one      = &g_udp_low_dist_ps;

        break;

    default:
        return -1;
    }

    /*
    **  Do detection on the different portscan types.
    */
    if ((config->detect_scan_type & PS_TYPE_PORTSCAN) &&
        ps_alert_one_to_one(scanner, scanned, one_to_one))
    {
        return 0;
    }

    if ((config->detect_scan_type & PS_TYPE_DECOYSCAN) &&
        ps_alert_one_to_one_decoy(scanner, scanned, one_to_one_decoy))
    {
        return 0;
    }

    if ((config->detect_scan_type & PS_TYPE_PORTSWEEP) &&
        ps_alert_one_to_many(scanner, scanned, one_to_many))
    {
        return 0;
    }

    if ((config->detect_scan_type & PS_TYPE_DISTPORTSCAN) &&
        ps_alert_many_to_one(scanner, scanned, many_to_one))
    {
        return 0;
    }

    return 0;
}

int PortScan::ps_alert_icmp(PS_PROTO* scanner, PS_PROTO* scanned)
{
    static THREAD_LOCAL const PS_ALERT_CONF* one_to_many;

    /*
    ** Set the configurations depending on the sensitivity
    ** level.
    */
    switch (config->sense_level)
    {
    case PS_SENSE_HIGH:
        one_to_many = &g_icmp_hi_sweep;

        break;

    case PS_SENSE_MEDIUM:
        one_to_many = &g_icmp_med_sweep;

        break;

    case PS_SENSE_LOW:
        one_to_many = &g_icmp_low_sweep;

        break;

    default:
        return -1;
    }

    /*
    **  Do detection on the different portscan types.
    */
    if ((config->detect_scan_type & PS_TYPE_PORTSWEEP) &&
        ps_alert_one_to_many(scanner, scanned, one_to_many))
    {
        return 0;
    }

    return 0;
}

/*
**  NAME
**    ps_tracker_alert::
*/
/**
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
int PortScan::ps_tracker_alert(PS_PKT* ps_pkt, PS_TRACKER* scanner,
    PS_TRACKER* scanned)
{
    if (!ps_pkt)
        return -1;

    switch (ps_pkt->proto)
    {
    case PS_PROTO_TCP:
        ps_alert_tcp((scanner ? &scanner->proto : NULL),
            (scanned ? &scanned->proto : NULL));
        break;

    case PS_PROTO_UDP:
        ps_alert_udp((scanner ? &scanner->proto : NULL),
            (scanned ? &scanned->proto : NULL));
        break;

    case PS_PROTO_ICMP:
        ps_alert_icmp((scanner ? &scanner->proto : NULL),
            (scanned ? &scanned->proto : NULL));
        break;

    case PS_PROTO_IP:
        ps_alert_ip((scanner ? &scanner->proto : NULL),
            (scanned ? &scanned->proto : NULL));
        break;

    default:
        return -1;
    }

    return 0;
}

/*
**  NAME
**    ps_detect::
*/
/**
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
    PS_TRACKER* scanner = NULL;
    PS_TRACKER* scanned = NULL;
    int check_tcp_rst_other_dir = 1;
    Packet* p;

    if (!ps_pkt || !ps_pkt->pkt)
        return -1;

    if (ps_filter_ignore(ps_pkt))
        return 0;

    p = (Packet*)ps_pkt->pkt;

    do
    {
        if (ps_tracker_lookup(ps_pkt, &scanner, &scanned))
            return 0;

        if (ps_tracker_update(ps_pkt, scanner, scanned))
            return 0;

        if (ps_tracker_alert(ps_pkt, scanner, scanned))
            return 0;

        /* This is added to address the case of no
         * session and a RST packet going back from the Server. */
        if ( p->ptrs.tcph && (p->ptrs.tcph->th_flags & TH_RST) && !p->flow )
        {
            if (ps_pkt->reverse_pkt == 1)
            {
                check_tcp_rst_other_dir = 0;
            }
            else
            {
                ps_pkt->reverse_pkt = 1;
            }
        }
        else
        {
            check_tcp_rst_other_dir = 0;
        }
    }
    while (check_tcp_rst_other_dir);

    //printf("** alert\n");
    ps_pkt->scanner = scanner;
    ps_pkt->scanned = scanned;

    return 1;
}

