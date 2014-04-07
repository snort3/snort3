/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "decode.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include "decode_module.h"
#include "analyzer.h"
#include "snort.h"
#include "snort_debug.h"
#include "util.h"
#include "detect.h"
#include "checksum.h"
#include "log_text.h"
#include "generators.h"
#include "packet_io/active.h"
#include "sfxhash.h"
#include "snort_bounds.h"
#include "sf_iph.h"
#include "fpdetect.h"
#include "profiler.h"
#include "mempool/mempool.h"
#include "normalize/normalize.h"
#include "perf_monitor/perf.h"
#include "packet_io/sfdaq.h"

struct DecodeCounts
{
    PegCount total_processed;
    PegCount eth;
    PegCount vlan;
    PegCount nested_vlan;
    PegCount mpls;

    PegCount arp;
    PegCount ip;
    PegCount frags;
    PegCount tcp;
    PegCount udp;
    PegCount icmp;
    PegCount other;

    PegCount ipv6;
    PegCount tcp6;
    PegCount udp6;
    PegCount teredo;

    PegCount ipv6_up;
    PegCount ipv6_upfail;
    PegCount ipv6opts;
    PegCount ipv6disc;
    PegCount ip6ext;
    PegCount frag6;
    PegCount icmp6;

    PegCount embdip;
    PegCount ipx;
    PegCount ethloopback;

    PegCount ip4ip4;
    PegCount ip4ip6;
    PegCount ip6ip4;
    PegCount ip6ip6;

    PegCount gre;
    PegCount gre_ip;
    PegCount gre_eth;
    PegCount gre_arp;
    PegCount gre_ipv6;
    PegCount gre_ipv6ext;
    PegCount gre_ipx;
    PegCount gre_loopback;
    PegCount gre_vlan;
    PegCount gre_ppp;

    PegCount ethdisc;
    PegCount tdisc;
    PegCount udisc;
    PegCount icmpdisc;
    PegCount ipdisc;
    PegCount invalid_checksums;
    PegCount bad_ttl;
    PegCount discards;

#ifndef NO_NON_ETHER_DECODER
    PegCount eapol;
#ifdef DLT_IEEE802_11
  /* wireless statistics */
    PegCount wifi_mgmt;
    PegCount wifi_data;
    PegCount wifi_control;
    PegCount assoc_req;
    PegCount assoc_resp;
    PegCount reassoc_req;
    PegCount reassoc_resp;
    PegCount probe_req;
    PegCount probe_resp;
    PegCount beacon;
    PegCount atim;
    PegCount dissassoc;
    PegCount auth;
    PegCount deauth;
    PegCount ps_poll;
    PegCount rts;
    PegCount cts;
    PegCount ack;
    PegCount cf_end;
    PegCount cf_end_cf_ack;
    PegCount data;
    PegCount data_cf_ack;
    PegCount data_cf_poll;
    PegCount data_cf_ack_cf_poll;
    PegCount cf_ack;
    PegCount cf_poll;
    PegCount cf_ack_cf_poll;
#endif
#endif  // NO_NON_ETHER_DECODER
};

static const char* dc_pegs[] =
{
    "total",
    "eth",
    "vlan",
    "nested vlan",
    "mpls",

    "arp",
    "ip",
    "frags",
    "tcp",
    "udp",
    "icmp",
    "other",

    "ipv6",
    "tcp6",
    "udp6",
    "teredo",

    "ipv6 up",
    "ipv6 upfail",
    "ipv6opts",
    "ipv6disc",
    "ip6ext",
    "frag6",
    "icmp6",

    "embdip",
    "ipx",
    "ethloopback",

    "ip4ip4",
    "ip4ip6",
    "ip6ip4",
    "ip6ip6",

    "gre",
    "gre ip",
    "gre eth",
    "gre arp",
    "gre ipv6",
    "gre ipv6ext",
    "gre ipx",
    "gre loopback",
    "gre vlan",
    "gre ppp",

    "ethdisc",
    "tcp discards",
    "udp discards",
    "icmp discards",
    "ip discards",
    "invalid checksums",
    "bad ttl",
    "discards",

#ifndef NO_NON_ETHER_DECODER
    "eapol",
#ifdef DLT_IEEE802_11
  /* wireless statistics */
    "wifi mgmt",
    "wifi data",
    "wifi control",
    "assoc req",
    "assoc resp",
    "reassoc req",
    "reassoc resp",
    "probe req",
    "probe resp",
    "beacon",
    "atim",
    "dissassoc",
    "auth",
    "deauth",
    "ps poll",
    "rts",
    "cts",
    "ack",
    "cf end",
    "cf end cf ack",
    "data",
    "data cf ack",
    "data cf poll",
    "data cf ack cf poll",
    "cf ack",
    "cf poll",
    "cf ack cf poll",
#endif
#endif  // NO_NON_ETHER_DECODER
};

static DecodeCounts gdc;
static THREAD_LOCAL DecodeCounts dc;

void decoder_sum()
{
    sum_stats((PegCount*)&gdc, (PegCount*)&dc, array_size(dc_pegs));
    memset(&dc, 0, sizeof(dc));
}

void decoder_stats()
{
    show_percent_stats((PegCount*)&gdc, dc_pegs, array_size(dc_pegs),
        "decoder");
}

static IpAddrSet *SynToMulticastDstIp = NULL;

#ifdef PERF_PROFILING
THREAD_LOCAL PreprocStats decodePerfStats;
#endif

//--------------------------------------------------------------------
// decode.c::event support
//--------------------------------------------------------------------

static inline int ScNormalDrop (NormFlags nf)
{
    return !Normalize_IsEnabled(snort_conf, nf);
}

static inline void execTtlDrop (Packet* p)
{
    if ( ScNormalDrop(NORM_IP4_TTL) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
           "Dropping bad packet (IP4 TTL)\n"););
        p->error_flags |= PKT_ERR_BAD_TTL;
        Active_DropPacket();
        dc.bad_ttl++;
    }
}

static inline void execHopDrop (Packet* p)
{
    if ( ScNormalDrop(NORM_IP6_TTL) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
           "Dropping bad packet (IP6 hop limit)\n"););
        p->error_flags |= PKT_ERR_BAD_TTL;
        Active_DropPacket();
        dc.bad_ttl++;
    }
}

static inline void execIpChksmDrop (Packet*)
{
    // TBD only set policy csum drop if policy inline
    // and delete this inline mode check
    if( ScInlineMode() && ScIpChecksumDrops() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Dropping bad packet (IP checksum)\n"););
        Active_DropPacket();
    }
}

static inline void execTcpChksmDrop (Packet*)
{
    if( ScInlineMode() && ScTcpChecksumDrops() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Dropping bad packet (TCP checksum)\n"););
        Active_DropPacket();
    }
}

static inline void execUdpChksmDrop (Packet*)
{
    if( ScInlineMode() && ScUdpChecksumDrops() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Dropping bad packet (UDP checksum)\n"););
        Active_DropPacket();
    }
}

static inline void execIcmpChksmDrop (Packet*)
{
    if( ScInlineMode() && ScIcmpChecksumDrops() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Dropping bad packet (ICMP checksum)\n"););
        Active_DropPacket();
    }
}

static inline void DecoderEvent (Packet *p, int sid)
{
    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return;

    if ( ScLogVerbose() )
        ErrorMessage("%d:%d\n", GID_DECODE, sid);

    SnortEventqAdd(GID_DECODE, sid);
}

static inline void DecoderDrop (
    Packet *p, int sid, void (*callback)(Packet*) )
{
    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return;

    if ( ScLogVerbose() )
        ErrorMessage("%d:%d\n", GID_DECODE, sid);

    SnortEventqAdd(GID_DECODE, sid);
    callback(p);
}

void DecoderAlertEncapsulated(
    Packet *p, int sid, const uint8_t *pkt, uint32_t len)
{
    DecoderEvent(p, sid);

    p->data = pkt;
    p->dsize = (uint16_t)len;

    p->greh = NULL;
}

//--------------------------------------------------------------------
// decode.c::miscellaneous public methods and helper functions
//--------------------------------------------------------------------

#if defined(WORDS_MUSTALIGN) && !defined(__GNUC__)
uint32_t EXTRACT_32BITS (u_char *p)
{
  uint32_t __tmp;

  memmove(&__tmp, p, sizeof(uint32_t));
  return (uint32_t) ntohl(__tmp);
}
#endif /* WORDS_MUSTALIGN && !__GNUC__ */

void InitSynToMulticastDstIp( SnortConfig* sc )
{
    SynToMulticastDstIp = IpAddrSetParse(sc, "[232.0.0.0/8,233.0.0.0/8,239.0.0.0/8]");

    if( SynToMulticastDstIp == NULL )
    {
        FatalError("Could not initialize SynToMulticastDstIp\n");
    }
}

void SynToMulticastDstIpDestroy( void )
{

    if( SynToMulticastDstIp )
    {
        IpAddrSetDestroy(SynToMulticastDstIp);
    }
}

static inline void CheckIPv4_MinTTL(Packet *p, uint8_t ttl)
{

    // this sequence of tests is best for the "normal" case where
    // the packet ttl is >= the configured min (the default is 1)
    if( ttl < ScMinTTL() )
    {
        if ( ttl == 0 )
        {
            DecoderDrop(p, DECODE_ZERO_TTL, execTtlDrop);
        }
        else
        {
            DecoderDrop(p, DECODE_IP4_MIN_TTL, execTtlDrop);
        }
    }
}

static inline void CheckIPv6_MinTTL(Packet *p, uint8_t hop_limit)
{
    // this sequence of tests is best for the "normal" case where
    // the packet ttl is >= the configured min (the default is 1)
    if( hop_limit < ScMinTTL() )
    {
        if ( hop_limit == 0 )
        {
            DecoderDrop(p, DECODE_IP6_ZERO_HOP_LIMIT, execHopDrop);
        }
        else
        {
            DecoderDrop(p, DECODE_IPV6_MIN_TTL, execHopDrop);
        }
    }
}

/* Decoding of ttl/hop_limit is based on the policy min_ttl */
static inline void DecodeIP_MinTTL(Packet *p)
{
    switch(p->outer_family)
    {
        case AF_INET:
            CheckIPv4_MinTTL( p, p->outer_ip4h.ip_ttl);
            return;

        case AF_INET6:
            CheckIPv6_MinTTL( p, p->outer_ip6h.hop_lmt);
            return;

        default:
            break;
    }

    switch(p->family)
    {
        case AF_INET:
            CheckIPv4_MinTTL( p, p->ip4h->ip_ttl);
            return;

        case AF_INET6:
            CheckIPv6_MinTTL( p, p->ip6h->hop_lmt);
            return;

        default:
            break;
    }

    return;
}

// NOTE intermediate queue was eliminated in favor of directly queueing 
// and checking policy before logging
// FIXIT in order for config based checks like ttl and checksum to work,
// must select decoder policy after each applicable decode (eg vlan and ip)
// (checksums use next outer layer policy; ttl use current layer policy)
// FIXIT break up and put into appropriate decoder
// NOTE new bindings are not in place yet; must stub out for now
void DecodePolicySpecific(Packet *p)
{
    DecodeIP_MinTTL(p);
}

// this must be called iff the layer is successfully decoded because, when
// enabled, the normalizer assumes that the encoding is structurally sound
static inline void PushLayer(PROTO_ID type, Packet* p, const uint8_t* hdr, uint32_t len)
{
    if ( p->next_layer < LAYER_MAX )
    {
        Layer* lyr = p->layers + p->next_layer++;
        lyr->proto = type;
        lyr->start = (uint8_t*)hdr;
        lyr->length = (uint16_t)len;
    }
    else
    {
        LogMessage("(snort_decoder) WARNING: decoder got too many layers;"
            " next proto is %u.\n", type);
    }
}

//--------------------------------------------------------------------
// decode.c::ARP
//--------------------------------------------------------------------

/*
 * Function: DecodeARP(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode ARP stuff
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeARP(const uint8_t * pkt, uint32_t len, Packet * p)
{
    dc.arp++;

    if (p->greh != NULL)
        dc.gre_arp++;

    p->ah = (EtherARP *) pkt;

    if(len < sizeof(EtherARP))
    {
        DecoderEvent(p, DECODE_ARP_TRUNCATED);

        dc.discards++;
        return;
    }

    p->proto_bits |= PROTO_BIT__ARP;
    PushLayer(PROTO_ARP, p, pkt, sizeof(*p->ah));
}

//--------------------------------------------------------------------
// decode.c::NULL and Loopback
//--------------------------------------------------------------------

/*
 * Function: DecodeNullPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decoding on loopback devices.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeNullPkt(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"); );

    /* do a little validation */
    if(cap_len < NULL_HDRLEN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("NULL header length < captured len! (%d bytes)\n",
                    cap_len);
        }

        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    DecodeIP(p->pkt + NULL_HDRLEN, cap_len - NULL_HDRLEN, p);
    PREPROC_PROFILE_END(decodePerfStats);
}

/*
 * Function: DecodeEthLoopback(uint8_t *, uint32_t)
 *
 * Purpose: Just like IPX, it's just for counting.
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */
void DecodeEthLoopback(const uint8_t*, uint32_t, Packet *p)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "EthLoopback is not supported.\n"););

    dc.ethloopback++;

    if (p->greh != NULL)
        dc.gre_loopback++;

    return;
}

//--------------------------------------------------------------------
// decode.c::Ethernet
//--------------------------------------------------------------------

/*
 * Function: DecodeEthPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeEthPkt(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);
    dc.eth++;
    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)cap_len, (unsigned long)pkthdr->pktlen);
            );

    /* do a little validation */
    if(cap_len < ETHERNET_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "WARNING: Truncated eth header (%d bytes).\n", cap_len););

        DecoderEvent(p, DECODE_ETH_HDR_TRUNC);

        dc.discards++;
        dc.ethdisc++;
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    /* lay the ethernet structure over the packet data */
    p->eh = (EtherHdr *) pkt;
    PushLayer(PROTO_ETH, p, pkt, sizeof(*p->eh));

    DEBUG_WRAP(
            DebugMessage(DEBUG_DECODE, "%X:%X:%X:%X:%X:%X -> %X:%X:%X:%X:%X:%X\n",
                p->eh->ether_src[0],
                p->eh->ether_src[1], p->eh->ether_src[2], p->eh->ether_src[3],
                p->eh->ether_src[4], p->eh->ether_src[5], p->eh->ether_dst[0],
                p->eh->ether_dst[1], p->eh->ether_dst[2], p->eh->ether_dst[3],
                p->eh->ether_dst[4], p->eh->ether_dst[5]);
            );
    DEBUG_WRAP(
            DebugMessage(DEBUG_DECODE, "type:0x%X len:0x%X\n",
                ntohs(p->eh->ether_type), p->pkth->pktlen)
            );

    /* grab out the network type */
    switch(ntohs(p->eh->ether_type))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE,
                        "IP datagram size calculated to be %lu bytes\n",
                        (unsigned long)(cap_len - ETHERNET_HEADER_LEN));
                    );

            DecodeIP(p->pkt + ETHERNET_HEADER_LEN,
                    cap_len - ETHERNET_HEADER_LEN, p);

            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(p->pkt + ETHERNET_HEADER_LEN,
                    cap_len - ETHERNET_HEADER_LEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(p->pkt + ETHERNET_HEADER_LEN,
                    (cap_len - ETHERNET_HEADER_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_PPPoE_DISC:
        case ETHERNET_TYPE_PPPoE_SESS:
            DecodePPPoEPkt(p->pkt + ETHERNET_HEADER_LEN,
                    (cap_len - ETHERNET_HEADER_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

#ifndef NO_NON_ETHER_DECODER
        case ETHERNET_TYPE_IPX:
            DecodeIPX(p->pkt + ETHERNET_HEADER_LEN,
                    (cap_len - ETHERNET_HEADER_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;
#endif

        case ETHERNET_TYPE_LOOP:
            DecodeEthLoopback(p->pkt + ETHERNET_HEADER_LEN,
                    (cap_len - ETHERNET_HEADER_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + ETHERNET_HEADER_LEN,
                    cap_len - ETHERNET_HEADER_LEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_MPLS_MULTICAST:
            if(!ScMplsMulticast())
            {
                //additional check for DecoderAlerts will be done now.
            	DecoderEvent(p, DECODE_BAD_MPLS);
            }
        case ETHERNET_TYPE_MPLS_UNICAST:
                DecodeMPLS(p->pkt + ETHERNET_HEADER_LEN,
                    cap_len - ETHERNET_HEADER_LEN, p);
                PREPROC_PROFILE_END(decodePerfStats);
                return;

        default:
            // TBD add decoder drop event for unknown eth type
            dc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

/*
 * Function: DecodeTransBridging(uint8_t *, const uint32_t, Packet)
 *
 * Purpose: Decode Transparent Ethernet Bridging
 *
 * Arguments: pkt => pointer to the real live packet data
 *            len => length of remaining data in packet
 *            p => pointer to the decoded packet struct
 *
 *
 * Returns: void function
 *
 * Note: This is basically the code from DecodeEthPkt but the calling
 * convention needed to be changed and the stuff at the beginning
 * wasn't needed since we are already deep into the packet
 */
void DecodeTransBridging(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    dc.gre_eth++;

    if(len < ETHERNET_HEADER_LEN)
    {
        DecoderAlertEncapsulated(p, DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR, pkt, len);
        return;
    }

    /* The Packet struct's ethernet header will now point to the inner ethernet
     * header of the packet
     */
    p->eh = (EtherHdr *)pkt;
    PushLayer(PROTO_ETH, p, pkt, sizeof(*p->eh));

    switch (ntohs(p->eh->ether_type))
    {
        case ETHERNET_TYPE_IP:
            DecodeIP(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;

#ifndef NO_NON_ETHER_DECODER
        case ETHERNET_TYPE_IPX:
            DecodeIPX(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;
#endif

        case ETHERNET_TYPE_LOOP:
            DecodeEthLoopback(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, p);
            return;

        default:
            // TBD add decoder drop event for unknown xbrdg/eth type
            dc.other++;
            p->data = pkt + ETHERNET_HEADER_LEN;
            p->dsize = (uint16_t)(len - ETHERNET_HEADER_LEN);
            return;
    }
}

//--------------------------------------------------------------------
// decode.c::MPLS
//--------------------------------------------------------------------

/*
 * check if reserved labels are used properly
 */
static int checkMplsHdr(
    uint32_t label, uint8_t, uint8_t bos, uint8_t, Packet *p)
{
    int iRet = 0;
    switch(label)
    {
        case 0:
        case 2:
               /* check if this label is the bottom of the stack */
               if(bos)
               {
                   if ( label == 0 )
                       iRet = MPLS_PAYLOADTYPE_IPV4;
                   else if ( label == 2 )
                       iRet = MPLS_PAYLOADTYPE_IPV6;


                   /* when label == 2, IPv6 is expected;
                    * when label == 0, IPv4 is expected */
                   if((label&&(ScMplsPayloadType() != MPLS_PAYLOADTYPE_IPV6))
                       ||((!label)&&(ScMplsPayloadType() != MPLS_PAYLOADTYPE_IPV4)))
                   {
                        if( !label )
                            DecoderEvent(p, DECODE_BAD_MPLS_LABEL0);
                        else
                            DecoderEvent(p, DECODE_BAD_MPLS_LABEL2);
                   }
                   break;
               }

#if 0
               /* This is valid per RFC 4182.  Just pop this label off, ignore it
                * and move on to the next one.
                */
               if( !label )
                   DecoderEvent(p, DECODE_BAD_MPLS_LABEL0);
               else
                   DecoderEvent(p, DECODE_BAD_MPLS_LABEL2);

               dc.discards++;
               p->iph = NULL;
               p->family = NO_IP;
               return(-1);
#endif
               break;
        case 1:
               if(!bos) break;

       	       DecoderEvent(p, DECODE_BAD_MPLS_LABEL1);

               dc.discards++;
               p->iph = NULL;
               p->family = NO_IP;
               iRet = MPLS_PAYLOADTYPE_ERROR;
               break;

	    case 3:
               DecoderEvent(p, DECODE_BAD_MPLS_LABEL3);

               dc.discards++;
               p->iph = NULL;
               p->family = NO_IP;
               iRet = MPLS_PAYLOADTYPE_ERROR;
               break;
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
                DecoderEvent(p, DECODE_MPLS_RESERVED_LABEL);
                break;
        default:
                break;
    }
    if ( !iRet )
    {
        iRet = ScMplsPayloadType();
    }
    return iRet;
}

void DecodeMPLS(const uint8_t* pkt, const uint32_t len, Packet* p)
{
    uint32_t* tmpMplsHdr;
    uint32_t mpls_h;
    uint32_t label;
    uint32_t mlen = 0;

    uint8_t exp;
    uint8_t bos = 0;
    uint8_t ttl;
    uint8_t chainLen = 0;
    uint32_t stack_len = len;

    int iRet = 0;

    dc.mpls++;
    UpdateMPLSStats(&sfBase, len, Active_PacketWasDropped());
    tmpMplsHdr = (uint32_t *) pkt;
    p->mpls = NULL;

    while (!bos)
    {
        if(stack_len < MPLS_HEADER_LEN)
        {
            DecoderEvent(p, DECODE_BAD_MPLS);

            dc.discards++;
            p->iph = NULL;
            p->family = NO_IP;
            return;
        }

        mpls_h  = ntohl(*tmpMplsHdr);
        ttl = (uint8_t)(mpls_h & 0x000000FF);
        mpls_h = mpls_h>>8;
        bos = (uint8_t)(mpls_h & 0x00000001);
        exp = (uint8_t)(mpls_h & 0x0000000E);
        label = (mpls_h>>4) & 0x000FFFFF;

        if((label<NUM_RESERVED_LABELS)&&((iRet = checkMplsHdr(label, exp, bos, ttl, p)) < 0))
            return;

        if( bos )
        {
            p->mplsHdr.label = label;
            p->mplsHdr.exp = exp;
            p->mplsHdr.bos = bos;
            p->mplsHdr.ttl = ttl;
            /**
            p->mpls = &(p->mplsHdr);
			**/
            p->mpls = tmpMplsHdr;
            if(!iRet)
            {
                iRet = ScMplsPayloadType();
            }
        }
        tmpMplsHdr++;
        stack_len -= MPLS_HEADER_LEN;

        if ((ScMplsStackDepth() != -1) && (chainLen++ >= ScMplsStackDepth()))
        {
            DecoderEvent(p, DECODE_MPLS_LABEL_STACK);

            dc.discards++;
            p->iph = NULL;
            p->family = NO_IP;
            return;
        }
    }   /* while bos not 1, peel off more labels */

    mlen = (uint8_t*)tmpMplsHdr - pkt;
    PushLayer(PROTO_MPLS, p, pkt, mlen);
    mlen = len - mlen;

    switch (iRet)
    {
        case MPLS_PAYLOADTYPE_IPV4:
            DecodeIP((uint8_t *)tmpMplsHdr, mlen, p);
            break;

        case MPLS_PAYLOADTYPE_IPV6:
            DecodeIPV6((uint8_t *)tmpMplsHdr, mlen, p);
            break;

        case MPLS_PAYLOADTYPE_ETHERNET:
            DecodeEthOverMPLS((uint8_t *)tmpMplsHdr, mlen, p);
            break;

        default:
            break;
    }
    return;
}

void DecodeEthOverMPLS(const uint8_t* pkt, const uint32_t len, Packet* p)
{
    /* do a little validation */
    if(len < ETHERNET_HEADER_LEN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < Ethernet header length!"
                         " (%d bytes)\n", len);
        }

        p->iph = NULL;
        p->family = NO_IP;
        // TBD add decoder drop event for eth over MPLS cap len issue
        dc.discards++;
        dc.ethdisc++;
        return;
    }

    /* lay the ethernet structure over the packet data */
    p->eh = (EtherHdr *) pkt; // FIXTHIS squashes outer eth!
    PushLayer(PROTO_ETH, p, pkt, sizeof(*p->eh));

    DEBUG_WRAP(
            DebugMessage(DEBUG_DECODE, "%X   %X\n",
                *p->eh->ether_src, *p->eh->ether_dst);
            );

    /* grab out the network type */
    switch(ntohs(p->eh->ether_type))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE,
                        "IP datagram size calculated to be %lu bytes\n",
                        (unsigned long)(len - ETHERNET_HEADER_LEN));
                    );

            DecodeIP(p->pkt + ETHERNET_HEADER_LEN,
                    len - ETHERNET_HEADER_LEN, p);

            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(p->pkt + ETHERNET_HEADER_LEN,
                    len - ETHERNET_HEADER_LEN, p);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(p->pkt + ETHERNET_HEADER_LEN,
                    (len - ETHERNET_HEADER_LEN), p);
            return;

        case ETHERNET_TYPE_PPPoE_DISC:
        case ETHERNET_TYPE_PPPoE_SESS:
            DecodePPPoEPkt(p->pkt + ETHERNET_HEADER_LEN,
                    (len - ETHERNET_HEADER_LEN), p);
            return;

#ifndef NO_NON_ETHER_DECODER
        case ETHERNET_TYPE_IPX:
            DecodeIPX(p->pkt + ETHERNET_HEADER_LEN,
                    (len - ETHERNET_HEADER_LEN), p);
            return;
#endif

        case ETHERNET_TYPE_LOOP:
            DecodeEthLoopback(p->pkt + ETHERNET_HEADER_LEN,
                    (len - ETHERNET_HEADER_LEN), p);
            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + ETHERNET_HEADER_LEN,
                    len - ETHERNET_HEADER_LEN, p);
            return;

        default:
            // TBD add decoder drop event for unknown mpls/eth type
            dc.other++;
            return;
    }

    return;
}

int isPrivateIP(uint32_t addr)
{
    switch (addr & 0xff)
    {
        case 0x0a:
            return 1;
            break;
        case 0xac:
            if ((addr & 0xf000) == 0x1000)
                return 1;
            break;
        case 0xc0:
            if (((addr & 0xff00) ) == 0xa800)
                return 1;
            break;
    }
    return 0;
}

//--------------------------------------------------------------------
// decode.c::VLAN
//--------------------------------------------------------------------

#define LEN_VLAN_LLC_OTHER (sizeof(VlanTagHdr) + sizeof(EthLlc) + sizeof(EthLlcOther))

void DecodeVlan(const uint8_t * pkt, const uint32_t len, Packet * p)
{
    dc.vlan++;

    if (p->greh != NULL)
        dc.gre_vlan++;

    if(len < sizeof(VlanTagHdr))
    {
        DecoderEvent(p, DECODE_BAD_VLAN);

        // TBD add decoder drop event for VLAN hdr len issue
        dc.discards++;
        p->iph = NULL;
        p->family = NO_IP;
        return;
    }

    p->vh = (VlanTagHdr *) pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Vlan traffic:\n");
               DebugMessage(DEBUG_DECODE, "   Priority: %d(0x%X)\n",
                            VTH_PRIORITY(p->vh), VTH_PRIORITY(p->vh));
               DebugMessage(DEBUG_DECODE, "   CFI: %d\n", VTH_CFI(p->vh));
               DebugMessage(DEBUG_DECODE, "   Vlan ID: %d(0x%04X)\n",
                            VTH_VLAN(p->vh), VTH_VLAN(p->vh));
               DebugMessage(DEBUG_DECODE, "   Vlan Proto: 0x%04X\n",
                            ntohs(p->vh->vth_proto));
               );

    /* check to see if we've got an encapsulated LLC layer
     * http://www.geocities.com/billalexander/ethernet.html
     */
    if(ntohs(p->vh->vth_proto) <= ETHERNET_MAX_LEN_ENCAP)
    {
        if(len < sizeof(VlanTagHdr) + sizeof(EthLlc))
        {
            DecoderEvent(p, DECODE_BAD_VLAN_ETHLLC);

            dc.discards++;
            p->iph = NULL;
            p->family = NO_IP;
            return;
        }

        p->ehllc = (EthLlc *) (pkt + sizeof(VlanTagHdr));

        DEBUG_WRAP(
                DebugMessage(DEBUG_DECODE, "LLC Header:\n");
                DebugMessage(DEBUG_DECODE, "   DSAP: 0x%X\n", p->ehllc->dsap);
                DebugMessage(DEBUG_DECODE, "   SSAP: 0x%X\n", p->ehllc->ssap);
                );

        if(p->ehllc->dsap == ETH_DSAP_IP && p->ehllc->ssap == ETH_SSAP_IP)
        {
            if ( len < LEN_VLAN_LLC_OTHER )
            {
                DecoderEvent(p, DECODE_BAD_VLAN_OTHER);

                dc.discards++;
                p->iph = NULL;
                p->family = NO_IP;

                return;
            }

            p->ehllcother = (EthLlcOther *) (pkt + sizeof(VlanTagHdr) + sizeof(EthLlc));

            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE, "LLC Other Header:\n");
                    DebugMessage(DEBUG_DECODE, "   CTRL: 0x%X\n",
                        p->ehllcother->ctrl);
                    DebugMessage(DEBUG_DECODE, "   ORG: 0x%02X%02X%02X\n",
                        p->ehllcother->org_code[0], p->ehllcother->org_code[1],
                        p->ehllcother->org_code[2]);
                    DebugMessage(DEBUG_DECODE, "   PROTO: 0x%04X\n",
                        ntohs(p->ehllcother->proto_id));
                    );

            PushLayer(PROTO_VLAN, p, pkt, sizeof(*p->vh));

            switch(ntohs(p->ehllcother->proto_id))
            {
                case ETHERNET_TYPE_IP:
                    DecodeIP(p->pkt + LEN_VLAN_LLC_OTHER,
                             len - LEN_VLAN_LLC_OTHER, p);
                    return;

                case ETHERNET_TYPE_ARP:
                case ETHERNET_TYPE_REVARP:
                    DecodeARP(p->pkt + LEN_VLAN_LLC_OTHER,
                              len - LEN_VLAN_LLC_OTHER, p);
                    return;

                case ETHERNET_TYPE_IPV6:
                    DecodeIPV6(p->pkt + LEN_VLAN_LLC_OTHER,
                               len - LEN_VLAN_LLC_OTHER, p);
                    return;

                case ETHERNET_TYPE_8021Q:
                    dc.nested_vlan++;
                    DecodeVlan(p->pkt + LEN_VLAN_LLC_OTHER,
                               len - LEN_VLAN_LLC_OTHER, p);
                    return;

                case ETHERNET_TYPE_LOOP:
                    DecodeEthLoopback(p->pkt + LEN_VLAN_LLC_OTHER,
                                      len - LEN_VLAN_LLC_OTHER, p);
                    return;

#ifndef NO_NON_ETHER_DECODER
                case ETHERNET_TYPE_IPX:
                    DecodeIPX(p->pkt + LEN_VLAN_LLC_OTHER,
                              len - LEN_VLAN_LLC_OTHER, p);
                    return;
#endif

                case ETHERNET_TYPE_PPPoE_DISC:
                case ETHERNET_TYPE_PPPoE_SESS:
                    DecodePPPoEPkt(p->pkt + LEN_VLAN_LLC_OTHER,
                              len - LEN_VLAN_LLC_OTHER, p);
                    return;

                case ETHERNET_TYPE_MPLS_MULTICAST:
                    if(!ScMplsMulticast())
                    {
                        DecoderEvent(p, DECODE_BAD_MPLS);
                    }
                /* Fall through */
                case ETHERNET_TYPE_MPLS_UNICAST:
                    DecodeMPLS(p->pkt + LEN_VLAN_LLC_OTHER,
                        len - LEN_VLAN_LLC_OTHER, p);
                    return;

                default:
                    // TBD add decoder drop event for unknown vlan/eth type
                    dc.other++;
                    return;
            }
        }
    }
    else
    {
        PushLayer(PROTO_VLAN, p, pkt, sizeof(*p->vh));

        switch(ntohs(p->vh->vth_proto))
        {
            case ETHERNET_TYPE_IP:
                DecodeIP(pkt + sizeof(VlanTagHdr),
                         len - sizeof(VlanTagHdr), p);
                return;

            case ETHERNET_TYPE_ARP:
            case ETHERNET_TYPE_REVARP:
                DecodeARP(pkt + sizeof(VlanTagHdr),
                          len - sizeof(VlanTagHdr), p);
                return;

            case ETHERNET_TYPE_IPV6:
                DecodeIPV6(pkt +sizeof(VlanTagHdr),
                           len - sizeof(VlanTagHdr), p);
                return;

            case ETHERNET_TYPE_8021Q:
                dc.nested_vlan++;
                DecodeVlan(pkt + sizeof(VlanTagHdr),
                           len - sizeof(VlanTagHdr), p);
                return;

            case ETHERNET_TYPE_LOOP:
                DecodeEthLoopback(pkt + sizeof(VlanTagHdr),
                                  len - sizeof(VlanTagHdr), p);
                return;

#ifndef NO_NON_ETHER_DECODER
            case ETHERNET_TYPE_IPX:
                DecodeIPX(pkt + sizeof(VlanTagHdr),
                           len - sizeof(VlanTagHdr), p);
                return;
#endif

            case ETHERNET_TYPE_PPPoE_DISC:
            case ETHERNET_TYPE_PPPoE_SESS:
                DecodePPPoEPkt(pkt + sizeof(VlanTagHdr),
                               len - sizeof(VlanTagHdr), p);
                return;

            case ETHERNET_TYPE_MPLS_MULTICAST:
                if(!ScMplsMulticast())
                {
                    // FIXIT should be going to event queue
                    SnortEventqAdd(GID_DECODE, DECODE_BAD_MPLS);
                }
            case ETHERNET_TYPE_MPLS_UNICAST:
                DecodeMPLS(pkt + sizeof(VlanTagHdr),
                    len - sizeof(VlanTagHdr), p);
                return;

            default:
                // TBD add decoder drop event for unknown vlan/eth type
                dc.other++;
                return;
        }
    }

    // TBD add decoder drop event for unknown vlan/llc type
    dc.other++;
    return;
}

//--------------------------------------------------------------------
// decode.c::PPP related
//--------------------------------------------------------------------

/*
 * Function: DecodePPPoEPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
 * see http://www.faqs.org/rfcs/rfc2516.html
 *
 */
void DecodePPPoEPkt(const uint8_t* pkt, const uint32_t len, Packet* p)
{
    //PPPoE_Tag *ppppoe_tag=0;
    //PPPoE_Tag tag;  /* needed to avoid alignment problems */

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "PPPoE with len: %lu\n",
        (unsigned long)len););

    /* do a little validation */
    if(len < PPPOE_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Captured data length < PPPoE header length! "
            "(%d bytes)\n", len););

        DecoderEvent(p, DECODE_BAD_PPPOE);

        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "%X   %X\n",
                *p->eh->ether_src, *p->eh->ether_dst););

    /* lay the PPP over ethernet structure over the packet data */
    p->pppoeh = (PPPoEHdr *)pkt;

    /* grab out the network type */
    switch(ntohs(p->eh->ether_type))
    {
        case ETHERNET_TYPE_PPPoE_DISC:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "(PPPOE Discovery) "););
            break;

        case ETHERNET_TYPE_PPPoE_SESS:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "(PPPOE Session) "););
            break;

        default:
            return;
    }

#ifdef DEBUG_MSGS
    switch(p->pppoeh->code)
    {
        case PPPoE_CODE_PADI:
            /* The Host sends the PADI packet with the DESTINATION_ADDR set
             * to the broadcast address.  The CODE field is set to 0x09 and
             * the SESSION_ID MUST be set to 0x0000.
             *
             * The PADI packet MUST contain exactly one TAG of TAG_TYPE
             * Service-Name, indicating the service the Host is requesting,
             * and any number of other TAG types.  An entire PADI packet
             * (including the PPPoE header) MUST NOT exceed 1484 octets so
             * as to leave sufficient room for a relay agent to add a
             * Relay-Session-Id TAG.
             */
            DebugMessage(DEBUG_DECODE, "Active Discovery Initiation (PADI)\n");
            break;

        case PPPoE_CODE_PADO:
            /* When the Access Concentrator receives a PADI that it can
             * serve, it replies by sending a PADO packet.  The
             * DESTINATION_ADDR is the unicast address of the Host that
             * sent the PADI.  The CODE field is set to 0x07 and the
             * SESSION_ID MUST be set to 0x0000.
             *
             * The PADO packet MUST contain one AC-Name TAG containing the
             * Access Concentrator's name, a Service-Name TAG identical to
             * the one in the PADI, and any number of other Service-Name
             * TAGs indicating other services that the Access Concentrator
             * offers.  If the Access Concentrator can not serve the PADI
             * it MUST NOT respond with a PADO.
             */
            DebugMessage(DEBUG_DECODE, "Active Discovery Offer (PADO)\n");
            break;

        case PPPoE_CODE_PADR:
            /* Since the PADI was broadcast, the Host may receive more than
             * one PADO.  The Host looks through the PADO packets it receives
             * and chooses one.  The choice can be based on the AC-Name or
             * the Services offered.  The Host then sends one PADR packet
             * to the Access Concentrator that it has chosen.  The
             * DESTINATION_ADDR field is set to the unicast Ethernet address
             * of the Access Concentrator that sent the PADO.  The CODE
             * field is set to 0x19 and the SESSION_ID MUST be set to 0x0000.
             *
             * The PADR packet MUST contain exactly one TAG of TAG_TYPE
             * Service-Name, indicating the service the Host is requesting,
             * and any number of other TAG types.
             */
            DebugMessage(DEBUG_DECODE, "Active Discovery Request (PADR)\n");
            break;

        case PPPoE_CODE_PADS:
            /* When the Access Concentrator receives a PADR packet, it
             * prepares to begin a PPP session.  It generates a unique
             * SESSION_ID for the PPPoE session and replies to the Host with
             * a PADS packet.  The DESTINATION_ADDR field is the unicast
             * Ethernet address of the Host that sent the PADR.  The CODE
             * field is set to 0x65 and the SESSION_ID MUST be set to the
             * unique value generated for this PPPoE session.
             *
             * The PADS packet contains exactly one TAG of TAG_TYPE
             * Service-Name, indicating the service under which Access
             * Concentrator has accepted the PPPoE session, and any number
             * of other TAG types.
             *
             * If the Access Concentrator does not like the Service-Name in
             * the PADR, then it MUST reply with a PADS containing a TAG of
             * TAG_TYPE Service-Name-Error (and any number of other TAG
             * types).  In this case the SESSION_ID MUST be set to 0x0000.
             */
            DebugMessage(DEBUG_DECODE, "Active Discovery "
                         "Session-confirmation (PADS)\n");
            break;

        case PPPoE_CODE_PADT:
            /* This packet may be sent anytime after a session is established
             * to indicate that a PPPoE session has been terminated.  It may
             * be sent by either the Host or the Access Concentrator.  The
             * DESTINATION_ADDR field is a unicast Ethernet address, the
             * CODE field is set to 0xa7 and the SESSION_ID MUST be set to
             * indicate which session is to be terminated.  No TAGs are
             * required.
             *
             * When a PADT is received, no further PPP traffic is allowed to
             * be sent using that session.  Even normal PPP termination
             * packets MUST NOT be sent after sending or receiving a PADT.
             * A PPP peer SHOULD use the PPP protocol itself to bring down a
             * PPPoE session, but the PADT MAY be used when PPP can not be
             * used.
             */
            DebugMessage(DEBUG_DECODE, "Active Discovery Terminate (PADT)\n");
            break;

        case PPPoE_CODE_SESS:
            DebugMessage(DEBUG_DECODE, "Session Packet (SESS)\n");
            break;

        default:
            DebugMessage(DEBUG_DECODE, "(Unknown)\n");
            break;
    }
#endif

    if (ntohs(p->eh->ether_type) != ETHERNET_TYPE_PPPoE_DISC)
    {
        PushLayer(PROTO_PPPOE, p, pkt, PPPOE_HEADER_LEN);
        DecodePppPktEncapsulated(pkt + PPPOE_HEADER_LEN, len - PPPOE_HEADER_LEN, p);
        return;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Returning early on PPPOE discovery packet\n"););
        return;
    }

#if 0
    ppppoe_tag = (PPPoE_Tag *)(pkt + sizeof(PPPoEHdr));

    while (ppppoe_tag < (PPPoE_Tag *)(pkt + len))
    {
        if (((char*)(ppppoe_tag)+(sizeof(PPPoE_Tag)-1)) > (char*)(pkt + len))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Not enough data in packet for PPPOE Tag\n"););
            break;
        }

        /* no guarantee in PPPoE spec that ppppoe_tag is aligned at all... */
        memcpy(&tag, ppppoe_tag, sizeof(tag));

        DEBUG_WRAP(
                DebugMessage(DEBUG_DECODE, "\tPPPoE tag:\ntype: %04x length: %04x ",
                    ntohs(tag.type), ntohs(tag.length)););

#ifdef DEBUG_MSGS
        switch(ntohs(tag.type))
        {
            case PPPoE_TAG_END_OF_LIST:
                DebugMessage(DEBUG_DECODE, "(End of list)\n\t");
                break;
            case PPPoE_TAG_SERVICE_NAME:
                DebugMessage(DEBUG_DECODE, "(Service name)\n\t");
                break;
            case PPPoE_TAG_AC_NAME:
                DebugMessage(DEBUG_DECODE, "(AC Name)\n\t");
                break;
            case PPPoE_TAG_HOST_UNIQ:
                DebugMessage(DEBUG_DECODE, "(Host Uniq)\n\t");
                break;
            case PPPoE_TAG_AC_COOKIE:
                DebugMessage(DEBUG_DECODE, "(AC Cookie)\n\t");
                break;
            case PPPoE_TAG_VENDOR_SPECIFIC:
                DebugMessage(DEBUG_DECODE, "(Vendor Specific)\n\t");
                break;
            case PPPoE_TAG_RELAY_SESSION_ID:
                DebugMessage(DEBUG_DECODE, "(Relay Session ID)\n\t");
                break;
            case PPPoE_TAG_SERVICE_NAME_ERROR:
                DebugMessage(DEBUG_DECODE, "(Service Name Error)\n\t");
                break;
            case PPPoE_TAG_AC_SYSTEM_ERROR:
                DebugMessage(DEBUG_DECODE, "(AC System Error)\n\t");
                break;
            case PPPoE_TAG_GENERIC_ERROR:
                DebugMessage(DEBUG_DECODE, "(Generic Error)\n\t");
                break;
            default:
                DebugMessage(DEBUG_DECODE, "(Unknown)\n\t");
                break;
        }
#endif

#ifdef DEBUG_MSGS
        if (ntohs(tag.length) > 0)
        {
            char *buf;
            int i;

            switch (ntohs(tag.type))
            {
                case PPPoE_TAG_SERVICE_NAME:
                case PPPoE_TAG_AC_NAME:
                case PPPoE_TAG_SERVICE_NAME_ERROR:
                case PPPoE_TAG_AC_SYSTEM_ERROR:
                case PPPoE_TAG_GENERIC_ERROR: * ascii data *
                    buf = (char *)SnortAlloc(ntohs(tag.length) + 1);
                    strlcpy(buf, (char *)(ppppoe_tag+1), ntohs(tag.length));
                    DebugMessage(DEBUG_DECODE, "data (UTF-8): %s\n", buf);
                    free(buf);
                    break;

                case PPPoE_TAG_HOST_UNIQ:
                case PPPoE_TAG_AC_COOKIE:
                case PPPoE_TAG_RELAY_SESSION_ID:
                    DebugMessage(DEBUG_DECODE, "data (bin): ");
                    for (i = 0; i < ntohs(tag.length); i++)
                        DebugMessage(DEBUG_DECODE,
                                "%02x", *(((unsigned char *)ppppoe_tag) +
                                    sizeof(PPPoE_Tag) + i));
                    DebugMessage(DEBUG_DECODE, "\n");
                    break;

                default:
                    DebugMessage(DEBUG_DECODE, "unrecognized data\n");
                    break;
            }
        }
#endif

        ppppoe_tag = (PPPoE_Tag *)((char *)(ppppoe_tag+1)+ntohs(tag.length));
    }

#endif   /* #if 0 */

    return;
}

/*
 * Function: DecodePppPktEncapsulated(Packet *, const uint32_t len, uint8_t*)
 *
 * Purpose: Decode PPP traffic (RFC1661 framing).
 *
 * Arguments: p => pointer to decoded packet struct
 *            len => length of data to process
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodePppPktEncapsulated(const uint8_t* pkt, const uint32_t len, Packet* p)
{
    static THREAD_LOCAL int had_vj = 0;
    uint16_t protocol;
    uint32_t hlen = 1; /* HEADER - try 1 then 2 */

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "PPP Packet!\n"););

#ifdef WORDS_MUSTALIGN
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet with PPP header.  "
                            "PPP is only 1 or 2 bytes and will throw off "
                            "alignment on this architecture when decoding IP, "
                            "causing a bus error - stop decoding packet.\n"););

    p->data = pkt;
    p->dsize = (uint16_t)len;
    return;
#endif  /* WORDS_MUSTALIGN */

    if (p->greh != NULL)
        dc.gre_ppp++;

    /* do a little validation:
     *
     */
    if(len < 2)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Length not big enough for even a single "
                         "header or a one byte payload\n");
        }
        return;
    }


    if(pkt[0] & 0x01)
    {
        /* Check for protocol compression rfc1661 section 5
         *
         */
        hlen = 1;
        protocol = pkt[0];
    }
    else
    {
        protocol = ntohs(*((uint16_t *)pkt));
        hlen = 2;
    }

    /*
     * We only handle uncompressed packets. Handling VJ compression would mean
     * to implement a PPP state machine.
     */
    switch (protocol)
    {
        case PPP_VJ_COMP:
            if (!had_vj)
                ErrorMessage("PPP link seems to use VJ compression, "
                        "cannot handle compressed packets!\n");
            had_vj = 1;
            break;
        case PPP_VJ_UCOMP:
            /* VJ compression modifies the protocol field. It must be set
             * to tcp (only TCP packets can be VJ compressed) */
            if(len < (hlen + IP_HEADER_LEN))
            {
                if (ScLogVerbose())
                    ErrorMessage("PPP VJ min packet length > captured len! "
                                 "(%d bytes)\n", len);
                return;
            }

            ((IPHdr *)(pkt + hlen))->ip_proto = IPPROTO_TCP;
            /* fall through */

        case PPP_IP:
            PushLayer(PROTO_PPP_ENCAP, p, pkt, hlen);
            DecodeIP(pkt + hlen, len - hlen, p);
            break;

        case PPP_IPV6:
            PushLayer(PROTO_PPP_ENCAP, p, pkt, hlen);
            DecodeIPV6(pkt + hlen, len - hlen, p);
            break;

#ifndef NO_NON_ETHER_DECODER
        case PPP_IPX:
            PushLayer(PROTO_PPP_ENCAP, p, pkt, hlen);
            DecodeIPX(pkt + hlen, len - hlen, p);
            break;
#endif
    }
}

//--------------------------------------------------------------------
// decode.c::Raw packets
//--------------------------------------------------------------------

/*
 * Function: DecodeRawPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP.  Coded and
 *          in by Jed Pickle (thanks Jed!) and modified for a few little tweaks
 *          by me.
 *
 * Arguments: p => pointer to decoded packet struct
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeRawPkt(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Raw IP4 Packet!\n"););

    DecodeIP(pkt, p->pkth->caplen, p);

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

// raw packets are predetermined to be ip4 (above) or ip6 (below) by the DLT

void DecodeRawPkt6(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    PROFILE_VARS;
    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;
    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Raw IP6 Packet!\n"););

    DecodeIPV6(pkt, p->pkth->caplen, p);

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

//--------------------------------------------------------------------
// decode.c::IP4 misc
//--------------------------------------------------------------------

/*
 * Some IP Header tests
 * Land Attack(same src/dst ip)
 * Loopback (src or dst in 127/8 block)
 * Modified: 2/22/05-man for High Endian Architecture.
 */
#define IP4_THIS_NET  0x00  // msb
#define IP4_MULTICAST 0x0E  // ms nibble
#define IP4_RESERVED  0x0F  // ms nibble
#define IP4_LOOPBACK  0x7F  // msb
#define IP4_BROADCAST 0xffffffff

void IP4AddrTests (Packet* p)
{
    uint8_t msb_src, msb_dst;

    // check all 32 bits ...
    if( p->iph->ip_src.s_addr == p->iph->ip_dst.s_addr )
    {
        DecoderEvent(p, DECODE_BAD_TRAFFIC_SAME_SRCDST);

    }

    // check all 32 bits ...
    if ( p->iph->ip_src.s_addr == IP4_BROADCAST  )
        DecoderEvent(p, DECODE_IP4_SRC_BROADCAST);

    if ( p->iph->ip_dst.s_addr == IP4_BROADCAST  )
        DecoderEvent(p, DECODE_IP4_DST_BROADCAST);

    /* Loopback traffic  - don't use htonl for speed reasons -
     * s_addr is always in network order */
#ifdef WORDS_BIGENDIAN
    msb_src = (p->iph->ip_src.s_addr >> 24);
    msb_dst = (p->iph->ip_dst.s_addr >> 24);
#else
    msb_src = (uint8_t)(p->iph->ip_src.s_addr & 0xff);
    msb_dst = (uint8_t)(p->iph->ip_dst.s_addr & 0xff);
#endif
    // check the msb ...
    if ( msb_src == IP4_LOOPBACK || msb_dst == IP4_LOOPBACK )
    {
        DecoderEvent(p, DECODE_BAD_TRAFFIC_LOOPBACK);
    }
    // check the msb ...
    if ( msb_src == IP4_THIS_NET  )
        DecoderEvent(p, DECODE_IP4_SRC_THIS_NET);

    if ( msb_dst == IP4_THIS_NET  )
        DecoderEvent(p, DECODE_IP4_DST_THIS_NET);

    // check the 'msn' (most significant nibble) ...
    msb_src >>= 4;
    msb_dst >>= 4;

    if ( msb_src == IP4_MULTICAST )
        DecoderEvent(p, DECODE_IP4_SRC_MULTICAST);

    if ( msb_src == IP4_RESERVED )
        DecoderEvent(p, DECODE_IP4_SRC_RESERVED);

    if ( msb_dst == IP4_RESERVED )
        DecoderEvent(p, DECODE_IP4_DST_RESERVED);
}

static inline void ICMP4AddrTests (Packet* p)
{
    uint8_t msb_dst;

    uint32_t dst = GET_DST_IP(p)->ip32[0];

    // check all 32 bits; all set so byte order is irrelevant ...
    if ( dst == IP4_BROADCAST  )
        DecoderEvent(p, DECODE_ICMP4_DST_BROADCAST);

    /* - don't use htonl for speed reasons -
     * s_addr is always in network order */
#ifdef WORDS_BIGENDIAN
    msb_dst = (uint8_t)(dst >> 24);
#else
    msb_dst = (uint8_t)(dst & 0xff);
#endif

    // check the 'msn' (most significant nibble) ...
    msb_dst >>= 4;

    if ( msb_dst == IP4_MULTICAST )
        DecoderEvent(p, DECODE_ICMP4_DST_MULTICAST);
}

static inline void ICMP4MiscTests (Packet *p)
{
    {
        if ((p->dsize == 0) &&
            (p->icmph->type == ICMP_ECHO))
            DecoderEvent(p, DECODE_ICMP_PING_NMAP);
    }

    {
        if ((p->dsize == 0) &&
            (p->icmph->s_icmp_seq == 666))
            DecoderEvent(p, DECODE_ICMP_ICMPENUM);
    }

    {
        if ((p->icmph->code == 1) &&
            (p->icmph->type == ICMP_REDIRECT))
            DecoderEvent(p, DECODE_ICMP_REDIRECT_HOST);
    }

    {
        if ((p->icmph->type == ICMP_REDIRECT) &&
            (p->icmph->code == 0))
            DecoderEvent(p, DECODE_ICMP_REDIRECT_NET);
    }

    {
        if (p->icmph->type == ICMP_ECHOREPLY)
        {
            int i;
            for (i = 0; i < p->ip_option_count; i++)
            {
                if (p->ip_options[i].code == IPOPT_RR)
                    DecoderEvent(p, DECODE_ICMP_TRACEROUTE_IPOPTS);
            }
        }
    }

    {
        if ((p->icmph->type == ICMP_SOURCE_QUENCH) &&
            (p->icmph->code == 0))
            DecoderEvent(p, DECODE_ICMP_SOURCE_QUENCH);
    }

    {
        if ((p->dsize == 4) &&
            (p->icmph->type == ICMP_ECHO) &&
            (p->icmph->s_icmp_seq == 0) &&
            (p->icmph->code == 0))
            DecoderEvent(p, DECODE_ICMP_BROADSCAN_SMURF_SCANNER);
    }

    {
        if ((p->icmph->type == ICMP_DEST_UNREACH) &&
            (p->icmph->code == 13))
            DecoderEvent(p, DECODE_ICMP_DST_UNREACH_ADMIN_PROHIBITED);
    }

    {
        if ((p->icmph->type == ICMP_DEST_UNREACH) &&
            (p->icmph->code == 10))
            DecoderEvent(p, DECODE_ICMP_DST_UNREACH_DST_HOST_PROHIBITED);
    }

    {
        if ((p->icmph->type == ICMP_DEST_UNREACH) &&
            (p->icmph->code == 9))
            DecoderEvent(p, DECODE_ICMP_DST_UNREACH_DST_NET_PROHIBITED);
    }

}

/* IPv4-layer decoder rules */
static inline void IPMiscTests(Packet *p)
{
    {
        /* Yes, it's an ICMP-related vuln in IP options. */
        uint8_t i, length, pointer;

        /* Alert on IP packets with either 0x07 (Record Route) or 0x44 (Timestamp)
           options that are specially crafted. */
        for (i = 0; i < p->ip_option_count; i++)
        {
            if (p->ip_options[i].data == NULL)
                continue;

            if (p->ip_options[i].code == IPOPT_RR)
            {
                length = p->ip_options[i].len;
                if (length < 1)
                    continue;

                pointer = p->ip_options[i].data[0];

                /* If the pointer goes past the end of the data, then the data
                   is full. That's okay. */
                if (pointer >= length + 2)
                    continue;
                /* If the remaining space in the option isn't a multiple of 4
                   bytes, alert. */
                if (((length + 3) - pointer) % 4)
                    DecoderEvent(p, DECODE_ICMP_DOS_ATTEMPT);
            }
            else if (p->ip_options[i].code == IPOPT_TS)
            {
                length = p->ip_options[i].len;
                if (length < 2)
                    continue;

                pointer = p->ip_options[i].data[0];

                /* If the pointer goes past the end of the data, then the data
                   is full. That's okay. */
                if (pointer >= length + 2)
                    continue;
                /* If the remaining space in the option isn't a multiple of 4
                   bytes, alert. */
                if (((length + 3) - pointer) % 4)
                    DecoderEvent(p, DECODE_ICMP_DOS_ATTEMPT);
                /* If there is a timestamp + address, we need a multiple of 8
                   bytes instead. */
                if ((p->ip_options[i].data[1] & 0x01) && /* address flag */
                   (((length + 3) - pointer) % 8))
                    DecoderEvent(p, DECODE_ICMP_DOS_ATTEMPT);
            }
        }
    }
    {
        if (p->ip_option_count > 0)
            DecoderEvent(p, DECODE_IP_OPTION_SET);
    }

    {
        if (p->rf)
            DecoderEvent(p, DECODE_IP_RESERVED_FRAG_BIT);
    }
}

//--------------------------------------------------------------------
// decode.c::IP4 vulnerabilities
//--------------------------------------------------------------------

/* This PGM NAK function started off as an SO rule, sid 8351. */
static inline int pgm_nak_detect (uint8_t *data, uint16_t length) {
    uint16_t data_left;
    uint16_t  checksum;
    PGM_HEADER *header;

    if (NULL == data) {
        return PGM_NAK_ERR;
    }

    /* request must be bigger than 44 bytes to cause vuln */
    if (length <= sizeof(PGM_HEADER)) {
        return PGM_NAK_ERR;
    }

    header = (PGM_HEADER *) data;

    if (8 != header->type) {
        return PGM_NAK_ERR;
    }

    if (2 != header->nak.opt.type) {
        return PGM_NAK_ERR;
    }


    /*
     * alert if the amount of data after the options is more than the length
     * specified.
     */


    data_left = length - 36;
    if (data_left > header->nak.opt.len) {

        /* checksum is expensive... do that only if the length is bad */
        if (header->checksum != 0) {
            checksum = in_chksum_ip((unsigned short*)data, (int)length);
            if (checksum != 0)
                return PGM_NAK_ERR;
        }

        return PGM_NAK_VULN;
    }

    return PGM_NAK_OK;
}

static inline void CheckPGMVuln(Packet *p)
{
    if ( pgm_nak_detect((uint8_t *)p->data, p->dsize) == PGM_NAK_VULN )
        DecoderEvent(p, DECODE_PGM_NAK_OVERFLOW);
}

/* This function is a port of an old .so rule, sid 3:8092. */
static inline void CheckIGMPVuln(Packet *p)
{
    int i, alert = 0;

    if (p->dsize >= 1 && p->data[0] == 0x11)
    {
        if (p->ip_options_data != NULL) {
            if (p->ip_options_len >= 2) {
                if (*(p->ip_options_data) == 0 && *(p->ip_options_data+1) == 0)
                {
                    DecoderEvent(p, DECODE_IGMP_OPTIONS_DOS);
                    return;
                }
            }
        }

        for(i=0; i< (int) p->ip_option_count; i++) {
            /* All IGMPv2 packets contain IP option code 148 (router alert).
               This vulnerability only applies to IGMPv3, so return early. */
            if (p->ip_options[i].code == 148) {
                return; /* No alert. */
            }

            if (p->ip_options[i].len == 1) {
                alert++;
            }
        }

        if (alert > 0)
            DecoderEvent(p, DECODE_IGMP_OPTIONS_DOS);
    }
}

//--------------------------------------------------------------------
// decode.c::IP4 decoder
//--------------------------------------------------------------------

/* Function: DecodeIPv4Proto
 *
 * Gernalized IPv4 next protocol decoder dispatching.
 *
 * Arguments: proto => IPPROTO value of the next protocol
 *            pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the packet decode struct
 *
 */
static inline void DecodeIPv4Proto(const uint8_t proto,
    const uint8_t *pkt, const uint32_t len, Packet *p)
{
    switch(proto)
    {
        case IPPROTO_TCP:
            dc.tcp++;
            DecodeTCP(pkt, len, p);
            return;

        case IPPROTO_UDP:
            dc.udp++;
            DecodeUDP(pkt, len, p);
            return;

        case IPPROTO_ICMP:
            dc.icmp++;
            DecodeICMP(pkt, len, p);
            return;

        case IPPROTO_IPV6:
            if (len < 40)
            {
                /* Insufficient size for IPv6 Header. */
                /* This could be an attempt to exploit Linux kernel
                 * vulnerability, so log an alert */
                DecoderEvent(p, DECODE_IPV6_TUNNELED_IPV4_TRUNCATED);
            }
            dc.ip4ip6++;
            if ( ScTunnelBypassEnabled(TUNNEL_6IN4) )
                Active_SetTunnelBypass();
            DecodeIPV6(pkt, len, p);
            return;

        case IPPROTO_GRE:
            dc.gre++;
            DecodeGRE(pkt, len, p);
            return;

        case IPPROTO_IPIP:
            dc.ip4ip4++;
            DecodeIP(pkt, len, p);
            return;

        case IPPROTO_ESP:
            if (ScESPDecoding())
                DecodeESP(pkt, len, p);
            return;

        case IPPROTO_AH:
            DecodeAH(pkt, len, p);
            return;

        case IPPROTO_SWIPE:
        case IPPROTO_IP_MOBILITY:
        case IPPROTO_SUN_ND:
        case IPPROTO_PIM:
            DecoderEvent(p, DECODE_IP_BAD_PROTO);
            dc.other++;
            p->data = pkt;
            p->dsize = (uint16_t)len;
            return;

        case IPPROTO_PGM:
            dc.other++;
            p->data = pkt;
            p->dsize = (uint16_t)len;
            CheckPGMVuln(p);
            return;

        case IPPROTO_IGMP:
            dc.other++;
            p->data = pkt;
            p->dsize = (uint16_t)len;
            CheckIGMPVuln(p);
            return;

        default:
            {
                if (GET_IPH_PROTO(p) >= MIN_UNASSIGNED_IP_PROTO)
                    DecoderEvent(p, DECODE_IP_UNASSIGNED_PROTO);
            }
            dc.other++;
            p->data = pkt;
            p->dsize = (uint16_t)len;
            return;
    }
}

/*
 * Function: DecodeIP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the IP network layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the packet decode struct
 *
 * Returns: void function
 */
void DecodeIP(const uint8_t * pkt, const uint32_t len, Packet * p)
{
    uint32_t ip_len; /* length from the start of the ip hdr to the pkt end */
    uint32_t hlen;   /* ip header length */

    dc.ip++;

    if (p->greh != NULL)
        dc.gre_ip++;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    /* do a little validation */
    if(len < IP_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "WARNING: Truncated IP4 header (%d bytes).\n", len););

        DecoderEvent(p, DECODE_IP4_HDR_TRUNC);

        p->iph = NULL;
        p->family = NO_IP;

        dc.discards++;
        dc.ipdisc++;
        return;
    }

    if (p->family != NO_IP)
    {
        if (p->encapsulated)
        {
            DecoderAlertEncapsulated(p, DECODE_IP_MULTIPLE_ENCAPSULATION, pkt, len);

            return;
        }
        else
        {
            p->encapsulated = 1;
            p->outer_iph = p->iph;
            p->outer_ip_data = p->ip_data;
            p->outer_ip_dsize = p->ip_dsize;
        }
    }

    /* lay the IP struct over the raw data */
    p->inner_iph = p->iph = (IPHdr *)pkt;

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if(IP_VER((IPHdr*)pkt) != 4)
    {
        if ((p->packet_flags & PKT_UNSURE_ENCAP) == 0)
            DecoderEvent(p, DECODE_NOT_IPV4_DGRAM);

        p->iph = NULL;
        p->family = NO_IP;

        dc.discards++;
        dc.ipdisc++;
        return;
    }

    sfiph_build(p, p->iph, AF_INET);

    /* get the IP datagram length */
    ip_len = ntohs(p->iph->ip_len);

    /* get the IP header length */
    hlen = IP_HLEN(p->iph) << 2;

    /* header length sanity check */
    if(hlen < IP_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Bogus IP header length of %i bytes\n", hlen););

        DecoderEvent(p, DECODE_IPV4_INVALID_HEADER_LEN);

        p->iph = NULL;
        p->family = NO_IP;

        dc.discards++;
        dc.ipdisc++;
        return;
    }

    if (ip_len > len)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "IP Len field is %d bytes bigger than captured length.\n"
            "    (ip.len: %lu, cap.len: %lu)\n",
            ip_len - len, ip_len, len););

        DecoderEvent(p, DECODE_IPV4_DGRAM_GT_CAPLEN);

        p->iph = NULL;
        p->family = NO_IP;

        dc.discards++;
        dc.ipdisc++;
        return;
    }
#if 0
    // There is no need to alert when (ip_len < len).
    // Libpcap will capture more bytes than are part of the IP payload.
    // These could be Ethernet trailers, ESP trailers, etc.
    // This code is left in, commented, to keep us from re-writing it later.
    else if (ip_len < len)
    {
        if (ScLogVerbose())
            ErrorMessage("IP Len field is %d bytes "
                    "smaller than captured length.\n"
                    "    (ip.len: %lu, cap.len: %lu)\n",
                    len - ip_len, ip_len, len);
    }
#endif

    if(ip_len < hlen)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "IP dgm len (%d bytes) < IP hdr "
            "len (%d bytes), packet discarded\n", ip_len, hlen););

        DecoderEvent(p, DECODE_IPV4_DGRAM_LT_IPHDR);

        p->iph = NULL;
        p->family = NO_IP;

        dc.discards++;
        dc.ipdisc++;
        return;
    }

    /*
     * IP Header tests: Land attack, and Loop back test
     */
    IP4AddrTests(p);

    if (ScIpChecksums())
    {
        /* routers drop packets with bad IP checksums, we don't really
         * need to check them (should make this a command line/config
         * option
         */
        int16_t csum = in_chksum_ip((u_short *)p->iph, hlen);

        if(csum)
        {
            p->error_flags |= PKT_ERR_CKSUM_IP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad IP checksum\n"););

            execIpChksmDrop(p);
            dc.invalid_checksums++;
        }
#ifdef DEBUG_MSGS
        else
        {
            DebugMessage(DEBUG_DECODE, "IP Checksum: OK\n");
        }
#endif /* DEBUG */
    }

    PushLayer(PROTO_IP4, p, pkt, hlen);

    /* test for IP options */
    p->ip_options_len = (uint16_t)(hlen - IP_HEADER_LEN);

    if(p->ip_options_len > 0)
    {
        p->ip_options_data = pkt + IP_HEADER_LEN;
        DecodeIPOptions((pkt + IP_HEADER_LEN), p->ip_options_len, p);
    }
    else
    {
        /* If delivery header for GRE encapsulated packet is IP and it
         * had options, the packet's ip options will be refering to this
         * outer IP's options
         * Zero these options so they aren't associated with this inner IP
         * since p->iph will be pointing to this inner IP
         */
        if (p->encapsulated)
        {
            p->ip_options_data = NULL;
            p->ip_options_len = 0;
        }
        p->ip_option_count = 0;
    }

    /* set the real IP length for logging */
    p->actual_ip_len = (uint16_t) ip_len;

    /* set the remaining packet length */
    ip_len -= hlen;

    /* check for fragmented packets */
    p->frag_offset = ntohs(p->iph->ip_off);

    /*
     * get the values of the reserved, more
     * fragments and don't fragment flags
     */
    p->rf = (uint8_t)((p->frag_offset & 0x8000) >> 15);
    p->df = (uint8_t)((p->frag_offset & 0x4000) >> 14);
    p->mf = (uint8_t)((p->frag_offset & 0x2000) >> 13);

    /* mask off the high bits in the fragment offset field */
    p->frag_offset &= 0x1FFF;

    if ( p->df && p->frag_offset )
        DecoderEvent(p, DECODE_IP4_DF_OFFSET);

    if ( p->frag_offset + p->actual_ip_len > IP_MAXPACKET )
        DecoderEvent(p, DECODE_IP4_LEN_OFFSET);

    if(p->frag_offset || p->mf)
    {
        if ( !ip_len )
        {
            DecoderEvent(p, DECODE_ZERO_LENGTH_FRAG);
            p->frag_flag = 0;
        }
        else
        {
            /* set the packet fragment flag */
            p->frag_flag = 1;
            p->ip_frag_start = pkt + hlen;
            p->ip_frag_len = (uint16_t)ip_len;
            dc.frags++;
        }
    }
    else
    {
        p->frag_flag = 0;
    }

    {

        if( p->mf && p->df )
        {
            DecoderEvent(p, DECODE_BAD_FRAGBITS);
        }
    }

    /* Set some convienience pointers */
    p->ip_data = pkt + hlen;
    p->ip_dsize = (u_short) ip_len;

    /* See if there are any ip_proto only rules that match */
    fpEvalIpProtoOnlyRules(snort_conf->ip_proto_only_lists, p);

    p->proto_bits |= PROTO_BIT__IP;

    IPMiscTests(p);

    /* if this packet isn't a fragment
     * or if it is, its a UDP packet and offset is 0 */
    if(!(p->frag_flag) ||
            (p->frag_flag && (p->frag_offset == 0) &&
            (p->iph->ip_proto == IPPROTO_UDP)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IP header length: %lu\n",
                    (unsigned long)hlen););

        DecodeIPv4Proto(p->iph->ip_proto, pkt+hlen, ip_len, p);
    }
    else
    {
        /* set the payload pointer and payload size */
        p->data = pkt + hlen;
        p->dsize = (u_short) ip_len;
    }
}

//--------------------------------------------------------------------
// decode.c::ICMP
//--------------------------------------------------------------------

/*
 * Function: DecodeICMP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the ICMP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the decoded packet struct
 *
 * Returns: void function
 */
void DecodeICMP(const uint8_t * pkt, const uint32_t len, Packet * p)
{
    if(len < ICMP_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "WARNING: Truncated ICMP4 header (%d bytes).\n", len););

        DecoderEvent(p, DECODE_ICMP4_HDR_TRUNC);

        p->icmph = NULL;
        dc.discards++;
        dc.icmpdisc++;

        return;
    }

    /* set the header ptr first */
    p->icmph = (ICMPHdr *) pkt;

    switch (p->icmph->type)
    {
            // fall through ...
        case ICMP_SOURCE_QUENCH:
        case ICMP_DEST_UNREACH:
        case ICMP_REDIRECT:
        case ICMP_TIME_EXCEEDED:
        case ICMP_PARAMETERPROB:
        case ICMP_ECHOREPLY:
        case ICMP_ECHO:
        case ICMP_ROUTER_ADVERTISE:
        case ICMP_ROUTER_SOLICIT:
        case ICMP_INFO_REQUEST:
        case ICMP_INFO_REPLY:
            if (len < 8)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "Truncated ICMP header(%d bytes)\n", len););

                DecoderEvent(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                dc.discards++;
                dc.icmpdisc++;

                return;
            }
            break;

        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:
            if (len < 20)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "Truncated ICMP header(%d bytes)\n", len););

                DecoderEvent(p, DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR);

                p->icmph = NULL;
                dc.discards++;
                dc.icmpdisc++;

                return;
            }
            break;

        case ICMP_ADDRESS:
        case ICMP_ADDRESSREPLY:
            if (len < 12)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "Truncated ICMP header(%d bytes)\n", len););


                DecoderEvent(p, DECODE_ICMP_DGRAM_LT_ADDRHDR);

                p->icmph = NULL;
                dc.discards++;
                dc.icmpdisc++;

                return;
            }
            break;

        default:
            DecoderEvent(p, DECODE_ICMP4_TYPE_OTHER);
            break;
    }


    if (ScIcmpChecksums())
    {
        uint16_t csum = in_chksum_icmp((uint16_t *)p->icmph, len);

        if(csum)
        {
            p->error_flags |= PKT_ERR_CKSUM_ICMP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad ICMP Checksum\n"););
            execIcmpChksmDrop(p);
            dc.invalid_checksums++;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"ICMP Checksum: OK\n"););
        }
    }

    p->dsize = (u_short)(len - ICMP_HEADER_LEN);
    p->data = pkt + ICMP_HEADER_LEN;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP type: %d   code: %d\n",
                p->icmph->type, p->icmph->code););

    switch(p->icmph->type)
    {
        case ICMP_ECHO:
            ICMP4AddrTests(p);
        // fall through ...

        case ICMP_ECHOREPLY:
            /* setup the pkt id and seq numbers */
            /* add the size of the echo ext to the data
             * ptr and subtract it from the data size */
            p->dsize -= sizeof(ICMPHdr::icmp_hun.idseq);
            p->data += sizeof(ICMPHdr::icmp_hun.idseq);
            PushLayer(PROTO_ICMP4, p, pkt, ICMP_NORMAL_LEN);
            break;

        case ICMP_DEST_UNREACH:
            if ((p->icmph->code == ICMP_FRAG_NEEDED)
                    && (ntohs(p->icmph->s_icmp_nextmtu) < 576))
            {
                DecoderEvent(p, DECODE_ICMP_PATH_MTU_DOS);
            }

            /* Fall through */

        case ICMP_SOURCE_QUENCH:
        case ICMP_REDIRECT:
        case ICMP_TIME_EXCEEDED:
        case ICMP_PARAMETERPROB:
            /* account for extra 4 bytes in header */
            p->dsize -= 4;
            p->data += 4;

            PushLayer(PROTO_ICMP4, p, pkt, ICMP_NORMAL_LEN);
            DecodeICMPEmbeddedIP(p->data, p->dsize, p);
            break;

        default:
            PushLayer(PROTO_ICMP4, p, pkt, ICMP_HEADER_LEN);
            break;
    }

    /* Run a bunch of ICMP decoder rules */
    ICMP4MiscTests(p);

    p->proto_bits |= PROTO_BIT__ICMP;
    p->proto_bits &= ~(PROTO_BIT__UDP | PROTO_BIT__TCP);
}

/*
 * Function: DecodeICMPEmbeddedIP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the ICMP embedded IP header + 64 bits payload
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to dummy packet decode struct
 *
 * Returns: void function
 */
void DecodeICMPEmbeddedIP(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    uint32_t ip_len;       /* length from the start of the ip hdr to the
                             * pkt end */
    uint32_t hlen;             /* ip header length */
    uint16_t orig_frag_offset;

    /* do a little validation */
    if(len < IP_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP: IP short header (%d bytes)\n", len););

        DecoderEvent(p, DECODE_ICMP_ORIG_IP_TRUNCATED);

        p->orig_family = NO_IP;
        p->orig_iph = NULL;
        return;
    }

    /* lay the IP struct over the raw data */
    sfiph_orig_build(p, pkt, AF_INET);
    p->orig_iph = (IPHdr *) pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "DecodeICMPEmbeddedIP: ip header"
                    " starts at: %p, length is %lu\n", p->orig_iph,
                    (unsigned long) len););
    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if((GET_ORIG_IPH_VER(p) != 4) && !IS_IP6(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP: not IPv4 datagram ([ver: 0x%x][len: 0x%x])\n",
            GET_ORIG_IPH_VER(p), GET_ORIG_IPH_LEN(p)););

        DecoderEvent(p, DECODE_ICMP_ORIG_IP_VER_MISMATCH);

        p->orig_family = NO_IP;
        p->orig_iph = NULL;
        return;
    }

    /* set the IP datagram length */
    ip_len = ntohs(GET_ORIG_IPH_LEN(p));

    /* set the IP header length */
    hlen = (p->orig_ip4h->ip_verhl & 0x0f) << 2;

    if(len < hlen)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP: IP len (%d bytes) < IP hdr len (%d bytes), packet discarded\n",
            ip_len, hlen););

        DecoderEvent(p, DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP);

        p->orig_family = NO_IP;
        p->orig_iph = NULL;
        return;
    }

    /* set the remaining packet length */
    ip_len = len - hlen;

    orig_frag_offset = ntohs(GET_ORIG_IPH_OFF(p));
    orig_frag_offset &= 0x1FFF;

    if (orig_frag_offset == 0)
    {
        /* Original IP payload should be 64 bits */
        if (ip_len < 8)
        {
            DecoderEvent(p, DECODE_ICMP_ORIG_PAYLOAD_LT_64);

            return;
        }
        /* ICMP error packets could contain as much of original payload
         * as possible, but not exceed 576 bytes
         */
        else if (ntohs(GET_IPH_LEN(p)) > 576)
        {
            DecoderEvent(p, DECODE_ICMP_ORIG_PAYLOAD_GT_576);
        }
    }
    else
    {
        /* RFC states that only first frag will get an ICMP response */
        DecoderEvent(p, DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET);
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP Unreachable IP header length: "
                            "%lu\n", (unsigned long)hlen););

    switch(GET_ORIG_IPH_PROTO(p))
    {
        case IPPROTO_TCP: /* decode the interesting part of the header */
            p->orig_tcph = (TCPHdr *)(pkt + hlen);

            /* stuff more data into the printout data struct */
            p->orig_sp = ntohs(p->orig_tcph->th_sport);
            p->orig_dp = ntohs(p->orig_tcph->th_dport);

            break;

        case IPPROTO_UDP:
            p->orig_udph = (UDPHdr *)(pkt + hlen);

            /* fill in the printout data structs */
            p->orig_sp = ntohs(p->orig_udph->uh_sport);
            p->orig_dp = ntohs(p->orig_udph->uh_dport);

            break;

        case IPPROTO_ICMP:
            p->orig_icmph = (ICMPHdr *)(pkt + hlen);
            break;
    }

    return;
}

/*
 * Function: DecodeIPV6(uint8_t *, uint32_t)
 *
 * Purpose: Decoding IPv6 headers
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 */

//--------------------------------------------------------------------
// decode.c::IP6 misc
//--------------------------------------------------------------------

#define IP6_MULTICAST  0xFF  // first/most significant octet
#define IP6_MULTICAST_SCOPE_RESERVED    0x00
#define IP6_MULTICAST_SCOPE_INTERFACE   0x01
#define IP6_MULTICAST_SCOPE_LINK        0x02
#define IP6_MULTICAST_SCOPE_ADMIN       0x04
#define IP6_MULTICAST_SCOPE_SITE        0x05
#define IP6_MULTICAST_SCOPE_ORG         0x08
#define IP6_MULTICAST_SCOPE_GLOBAL      0x0E

/* Check for multiple IPv6 Multicast-related alerts */
static void CheckIPV6Multicast(Packet *p)
{
    uint8_t multicast_scope;

    if ( p->ip6h->ip_src.ip.u6_addr8[0] == IP6_MULTICAST )
    {
        DecoderEvent(p, DECODE_IPV6_SRC_MULTICAST);
    }
    if ( p->ip6h->ip_dst.ip.u6_addr8[0] != IP6_MULTICAST )
    {
        return;
    }

    multicast_scope = p->ip6h->ip_dst.ip.u6_addr8[1] & 0x0F;
    switch (multicast_scope)
    {
        case IP6_MULTICAST_SCOPE_RESERVED:
        case IP6_MULTICAST_SCOPE_INTERFACE:
        case IP6_MULTICAST_SCOPE_LINK:
        case IP6_MULTICAST_SCOPE_ADMIN:
        case IP6_MULTICAST_SCOPE_SITE:
        case IP6_MULTICAST_SCOPE_ORG:
        case IP6_MULTICAST_SCOPE_GLOBAL:
            break;

        default:
            DecoderEvent(p, DECODE_IPV6_BAD_MULTICAST_SCOPE);
    }

    /* Check against assigned multicast addresses. These are listed at:
       http://www.iana.org/assignments/ipv6-multicast-addresses/    */

    /* Multicast addresses only specify the first 16 and last 40 bits.
       Others should be zero. */
    if ((p->ip6h->ip_dst.ip.u6_addr16[1] != 0) ||
        (p->ip6h->ip_dst.ip.u6_addr16[2] != 0) ||
        (p->ip6h->ip_dst.ip.u6_addr16[3] != 0) ||
        (p->ip6h->ip_dst.ip.u6_addr16[4] != 0) ||
        (p->ip6h->ip_dst.ip.u6_addr8[10] != 0))
    {
        DecoderEvent(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
        return;
    }

    if (p->ip6h->ip_dst.ip.u6_addr8[1] == IP6_MULTICAST_SCOPE_INTERFACE)
    {
        // Node-local scope
        if ((p->ip6h->ip_dst.ip.u6_addr16[1] != 0) ||
            (p->ip6h->ip_dst.ip.u6_addr16[2] != 0) ||
            (p->ip6h->ip_dst.ip.u6_addr16[3] != 0) ||
            (p->ip6h->ip_dst.ip.u6_addr16[4] != 0) ||
            (p->ip6h->ip_dst.ip.u6_addr16[5] != 0) ||
            (p->ip6h->ip_dst.ip.u6_addr16[6] != 0))
        {

            DecoderEvent(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
        else
        {
            switch (ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]))
            {
                case 0x00000001: // All Nodes
                case 0x00000002: // All Routers
                case 0x000000FB: // mDNSv6
                    break;
                default:
                    DecoderEvent(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
            }
        }
    }
    else if (p->ip6h->ip_dst.ip.u6_addr8[1] == IP6_MULTICAST_SCOPE_LINK)
    {
        // Link-local scope
        switch (ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]))
        {
            case 0x00000001: // All Nodes
            case 0x00000002: // All Routers
            case 0x00000004: // DVMRP Routers
            case 0x00000005: // OSPFIGP
            case 0x00000006: // OSPFIGP Designated Routers
            case 0x00000007: // ST Routers
            case 0x00000008: // ST Hosts
            case 0x00000009: // RIP Routers
            case 0x0000000A: // EIGRP Routers
            case 0x0000000B: // Mobile-Agents
            case 0x0000000C: // SSDP
            case 0x0000000D: // All PIMP Routers
            case 0x0000000E: // RSVP-ENCAPSULATION
            case 0x0000000F: // UPnP
            case 0x00000012: // VRRP
            case 0x00000016: // All MLDv2-capable routers
            case 0x0000006A: // All-Snoopers
            case 0x0000006B: // PTP-pdelay
            case 0x0000006C: // Saratoga
            case 0x0000006D: // LL-MANET-Routers
            case 0x0000006E: // IGRS
            case 0x0000006F: // iADT Discovery
            case 0x000000FB: // mDNSv6
            case 0x00010001: // Link Name
            case 0x00010002: // All-dhcp-agents
            case 0x00010003: // Link-local Multicast Name Resolution
            case 0x00010004: // DTCP Announcement
                break;
            default:
                if ((p->ip6h->ip_dst.ip.u6_addr8[11] == 1) &&
                    (p->ip6h->ip_dst.ip.u6_addr8[12] == 0xFF))
                {
                    break; // Solicited-Node Address
                }
                if ((p->ip6h->ip_dst.ip.u6_addr8[11] == 2) &&
                    (p->ip6h->ip_dst.ip.u6_addr8[12] == 0xFF))
                {
                    break; // Node Information Queries
                }
                DecoderEvent(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else if (p->ip6h->ip_dst.ip.u6_addr8[1] == IP6_MULTICAST_SCOPE_SITE)
    {
        // Site-local scope
        switch (ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]))
        {
            case 0x00000002: // All Routers
            case 0x000000FB: // mDNSv6
            case 0x00010003: // All-dhcp-servers
            case 0x00010004: // Deprecated
            case 0x00010005: // SL-MANET-ROUTERS
                break;
            default:
                DecoderEvent(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else if ((p->ip6h->ip_dst.ip.u6_addr8[1] & 0xF0) == 0)
    {
        // Variable scope
        switch (ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]))
        {
            case 0x0000000C: // SSDP
            case 0x000000FB: // mDNSv6
            case 0x00000181: // PTP-primary
            case 0x00000182: // PTP-alternate1
            case 0x00000183: // PTP-alternate2
            case 0x00000184: // PTP-alternate3
            case 0x0000018C: // All ACs multicast address
            case 0x00000201: // "rwho" Group (BSD)
            case 0x00000202: // SUN RPC PMAPPROC_CALLIT
            case 0x00000204: // All C1222 Nodes
            case 0x00000300: // Mbus/IPv6
            case 0x00027FFE: // SAPv1 Announcements
            case 0x00027FFF: // SAPv0 Announcements
                break;
            default:
                if ((ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) >= 0x00000100) &&
                    (ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) <= 0x00000136))
                {
                    break; // Several addresses assigned in a contiguous block
                }

                if ((ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) >= 0x00000140) &&
                    (ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) <= 0x0000014F))
                {
                    break; // EPSON-disc-set
                }

                if ((ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) >= 0x00020000) &&
                    (ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) <= 0x00027FFD))
                {
                    break; // Multimedia Conference Calls
                }

                if ((ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) >= 0x00011000) &&
                    (ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) <= 0x000113FF))
                {
                    break; // Service Location, Version 2
                }

                if ((ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) >= 0x00028000) &&
                    (ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) <= 0x0002FFFF))
                {
                    break; // SAP Dynamic Assignments
                }

                DecoderEvent(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else if ((p->ip6h->ip_dst.ip.u6_addr8[1] & 0xF0) == 0x30)
    {
        // Source-Specific Multicast block
        if ((ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) >= 0x40000001) &&
            (ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) <= 0x7FFFFFFF))
        {
            return; // IETF consensus
        }
        else if ((ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) >= 0x80000000) &&
            (ntohl(p->ip6h->ip_dst.ip.u6_addr32[3]) <= 0xFFFFFFFF))
        {
            return; // Dynamiclly allocated by hosts when needed
        }
        else
        {
            // Other addresses in this block are reserved.
            DecoderEvent(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else
    {
        /* Addresses not listed above are reserved. */
        DecoderEvent(p, DECODE_IPV6_DST_RESERVED_MULTICAST);
    }
}

/* Teredo packets need to have one of their IPs use either the Teredo prefix,
   or a link-local prefix (in the case of Router Solicitation messages) */
static inline int CheckTeredoPrefix(IP6RawHdr *hdr)
{
    /* Check if src address matches 2001::/32 */
    if ((hdr->ip6_src.s6_addr[0] == 0x20) &&
        (hdr->ip6_src.s6_addr[1] == 0x01) &&
        (hdr->ip6_src.s6_addr[2] == 0x00) &&
        (hdr->ip6_src.s6_addr[3] == 0x00))
        return 1;

    /* Check if src address matches fe80::/64 */
    if ((hdr->ip6_src.s6_addr[0] == 0xfe) &&
        (hdr->ip6_src.s6_addr[1] == 0x80) &&
        (hdr->ip6_src.s6_addr[2] == 0x00) &&
        (hdr->ip6_src.s6_addr[3] == 0x00) &&
        (hdr->ip6_src.s6_addr[4] == 0x00) &&
        (hdr->ip6_src.s6_addr[5] == 0x00) &&
        (hdr->ip6_src.s6_addr[6] == 0x00) &&
        (hdr->ip6_src.s6_addr[7] == 0x00))
        return 1;

    /* Check if dst address matches 2001::/32 */
    if ((hdr->ip6_dst.s6_addr[0] == 0x20) &&
        (hdr->ip6_dst.s6_addr[1] == 0x01) &&
        (hdr->ip6_dst.s6_addr[2] == 0x00) &&
        (hdr->ip6_dst.s6_addr[3] == 0x00))
        return 1;

    /* Check if dst address matches fe80::/64 */
    if ((hdr->ip6_dst.s6_addr[0] == 0xfe) &&
        (hdr->ip6_dst.s6_addr[1] == 0x80) &&
        (hdr->ip6_dst.s6_addr[2] == 0x00) &&
        (hdr->ip6_dst.s6_addr[3] == 0x00) &&
        (hdr->ip6_dst.s6_addr[4] == 0x00) &&
        (hdr->ip6_dst.s6_addr[5] == 0x00) &&
        (hdr->ip6_dst.s6_addr[6] == 0x00) &&
        (hdr->ip6_dst.s6_addr[7] == 0x00))
        return 1;

    /* No Teredo prefix found. */
    return 0;
}

/* Function: IPV6MiscTests(Packet *p)
 *
 * Purpose: A bunch of IPv6 decoder alerts
 *
 * Arguments: p => the Packet to check
 *
 * Returns: void function
 */
static inline void IPV6MiscTests(Packet *p)
{
    /*
     * Some IP Header tests
     * Land Attack(same src/dst ip)
     * Loopback (src or dst in 127/8 block)
     * Modified: 2/22/05-man for High Endian Architecture.
     *
     * some points in the code assume an IP of 0.0.0.0 matches anything, but
     * that is not so here.  The sfip_compare makes that assumption for
     * compatibility, but sfip_contains does not.  Hence, sfip_contains
     * is used here in the interrim. */
    if( sfip_contains(&p->ip6h->ip_src, &p->ip6h->ip_dst) == SFIP_CONTAINS)
    {
        DecoderEvent(p, DECODE_BAD_TRAFFIC_SAME_SRCDST);
    }

    if(sfip_is_loopback(&p->ip6h->ip_src) || sfip_is_loopback(&p->ip6h->ip_dst))
    {
        DecoderEvent(p, DECODE_BAD_TRAFFIC_LOOPBACK);
    }

    /* Other decoder alerts for IPv6 addresses
       Added: 5/24/10 (Snort 2.9.0) */
    if (!sfip_is_set(&p->ip6h->ip_dst))
    {
        DecoderEvent(p, DECODE_IPV6_DST_ZERO);
    }

    CheckIPV6Multicast(p);

    {
        /* Only check for IPv6 over IPv4 */
        if (p->ip4h && p->ip4h->ip_proto == IPPROTO_IPV6)
        {
            uint32_t isatap_interface_id = ntohl(p->ip6h->ip_src.ip.u6_addr32[2]) & 0xFCFFFFFF;

            /* ISATAP uses address with prefix fe80:0000:0000:0000:0200:5efe or
               fe80:0000:0000:0000:0000:5efe, followed by the IPv4 address. */
            if (isatap_interface_id == 0x00005EFE)
            {
                if (p->ip4h->ip_src.ip.u6_addr32[0] != p->ip6h->ip_src.ip.u6_addr32[3])
                    DecoderEvent(p, DECODE_IPV6_ISATAP_SPOOF);
            }
        }
    }
}

//--------------------------------------------------------------------
// decode.c::IP6 extensions
//--------------------------------------------------------------------

static inline int IPV6ExtensionOrder(uint8_t type)
{
    switch (type)
    {
        case IPPROTO_HOPOPTS:   return 1;
        case IPPROTO_DSTOPTS:   return 2;
        case IPPROTO_ROUTING:   return 3;
        case IPPROTO_FRAGMENT:  return 4;
        case IPPROTO_AH:        return 5;
        case IPPROTO_ESP:       return 6;
        default:                return 7;
    }
}

/* Check for out-of-order IPv6 Extension Headers */
static inline void CheckIPv6ExtensionOrder(Packet *p)
{
    int routing_seen = 0;
    int current_type_order, next_type_order, i;

    {
        if (p->ip6_extension_count > 0)
            current_type_order = IPV6ExtensionOrder(p->ip6_extensions[0].type);

        for (i = 1; i < (p->ip6_extension_count); i++)
        {
            next_type_order = IPV6ExtensionOrder(p->ip6_extensions[i].type);

            if (p->ip6_extensions[i].type == IPPROTO_ROUTING)
                routing_seen = 1;

            if (next_type_order <= current_type_order)
            {
                /* A second "Destination Options" header is allowed iff:
                   1) A routing header was already seen, and
                   2) The second destination header is the last one before the upper layer.
                */
                if (!routing_seen ||
                    !(p->ip6_extensions[i].type == IPPROTO_DSTOPTS) ||
                    !(i+1 == p->ip6_extension_count))
                {
                    DecoderEvent(p, DECODE_IPV6_UNORDERED_EXTENSIONS);
                }
            }

            current_type_order = next_type_order;
        }
    }
}

void DecodeIPV6Extensions(uint8_t next, const uint8_t *pkt, uint32_t len, Packet *p);

static inline int CheckIPV6HopOptions(const uint8_t *pkt, uint32_t len, Packet *p)
{
    IP6Extension *exthdr = (IP6Extension *)pkt;
    uint32_t total_octets = (exthdr->ip6e_len * 8) + 8;
    const uint8_t *hdr_end = pkt + total_octets;
    uint8_t type, oplen;

    if (len < total_octets)
        DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT);

    /* Skip to the options */
    pkt += 2;

    /* Iterate through the options, check for bad ones */
    while (pkt < hdr_end)
    {
        type = *pkt;
        switch (type)
        {
            case IP6_OPT_PAD1:
                pkt++;
                break;
            case IP6_OPT_PADN:
            case IP6_OPT_JUMBO:
            case IP6_OPT_RTALERT:
            case IP6_OPT_TUNNEL_ENCAP:
            case IP6_OPT_QUICK_START:
            case IP6_OPT_CALIPSO:
            case IP6_OPT_HOME_ADDRESS:
            case IP6_OPT_ENDPOINT_IDENT:
                oplen = *(++pkt);
                if ((pkt + oplen + 1) > hdr_end)
                {
                    DecoderEvent(p, DECODE_IPV6_BAD_OPT_LEN);
                    return -1;
                }
                pkt += oplen + 1;
                break;
            default:
                DecoderEvent(p, DECODE_IPV6_BAD_OPT_TYPE);
                return -1;
        }
    }

    return 0;
}

void DecodeIPV6Options(int type, const uint8_t *pkt, uint32_t len, Packet *p)
{
    IP6Extension *exthdr;
    uint32_t hdrlen = 0;

    /* This should only be called by DecodeIPV6 or DecodeIPV6Extensions
     * so no validation performed.  Otherwise, uncomment the following: */
    /* if(IPH_IS_VALID(p)) return */

    dc.ipv6opts++;

    /* Need at least two bytes, one for next header, one for len. */
    /* But size is an integer multiple of 8 octets, so 8 is min.  */
    if(len < sizeof(IP6Extension))
    {
        DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT);
        return;
    }

    if ( p->ip6_extension_count >= IP6_EXTMAX )
    {
        DecoderEvent(p, DECODE_IP6_EXCESS_EXT_HDR);
        return;
    }

    exthdr = (IP6Extension *)pkt;

    p->ip6_extensions[p->ip6_extension_count].type = type;
    p->ip6_extensions[p->ip6_extension_count].data = pkt;

    // TBD add layers for other ip6 ext headers
    switch (type)
    {
        case IPPROTO_HOPOPTS:
            if (len < sizeof(IP6HopByHop))
            {
                DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT);
                return;
            }
            hdrlen = sizeof(IP6Extension) + (exthdr->ip6e_len << 3);

            if ( CheckIPV6HopOptions(pkt, len, p) == 0 )
                PushLayer(PROTO_IP6_HOP_OPTS, p, pkt, hdrlen);
            break;

        case IPPROTO_DSTOPTS:
            if (len < sizeof(IP6Dest))
            {
                DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT);
                return;
            }
            if (exthdr->ip6e_nxt == IPPROTO_ROUTING)
            {
                DecoderEvent(p, DECODE_IPV6_DSTOPTS_WITH_ROUTING);
            }
            hdrlen = sizeof(IP6Extension) + (exthdr->ip6e_len << 3);

            if ( CheckIPV6HopOptions(pkt, len, p) == 0 )
                PushLayer(PROTO_IP6_DST_OPTS, p, pkt, hdrlen);
            break;

        case IPPROTO_ROUTING:
            if (len < sizeof(IP6Route))
            {
                DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT);
                return;
            }

            /* Routing type 0 extension headers are evil creatures. */
            {
                IP6Route *rte = (IP6Route *)exthdr;

                if (rte->ip6rte_type == 0)
                {
                    DecoderEvent(p, DECODE_IPV6_ROUTE_ZERO);
                }
            }

            if (exthdr->ip6e_nxt == IPPROTO_HOPOPTS)
            {
                DecoderEvent(p, DECODE_IPV6_ROUTE_AND_HOPBYHOP);
            }
            if (exthdr->ip6e_nxt == IPPROTO_ROUTING)
            {
                DecoderEvent(p, DECODE_IPV6_TWO_ROUTE_HEADERS);
            }
            hdrlen = sizeof(IP6Extension) + (exthdr->ip6e_len << 3);
            break;

        case IPPROTO_FRAGMENT:
            if (len <= sizeof(IP6Frag))
            {
                if ( len < sizeof(IP6Frag) )
                    DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT);
                else
                    DecoderEvent(p, DECODE_ZERO_LENGTH_FRAG);
                return;
            }
            else
            {
                IP6Frag *ip6frag_hdr = (IP6Frag *)pkt;
                /* If this is an IP Fragment, set some data... */
                p->ip6_frag_index = p->ip6_extension_count;
                p->ip_frag_start = pkt + sizeof(IP6Frag);

                p->df = 0;
                p->rf = IP6F_RES(ip6frag_hdr);
                p->mf = IP6F_MF(ip6frag_hdr);
                p->frag_offset = IP6F_OFFSET(ip6frag_hdr);

                if ( p->frag_offset || p->mf )
                {
                    p->frag_flag = 1;
                    dc.frag6++;
                }
                else
                {
                    DecoderEvent(p, DECODE_IPV6_BAD_FRAG_PKT);
                }
                if ( !(p->frag_offset) )
                {
                    // check header ordering of fragged (next) header
                    if ( IPV6ExtensionOrder(ip6frag_hdr->ip6f_nxt) <
                         IPV6ExtensionOrder(IPPROTO_FRAGMENT) )
                        DecoderEvent(p, DECODE_IPV6_UNORDERED_EXTENSIONS);
                }
                // check header ordering up thru frag header
                CheckIPv6ExtensionOrder(p);
            }
            hdrlen = sizeof(IP6Frag);
            p->ip_frag_len = (uint16_t)(len - hdrlen);

            if ( p->frag_flag && ((p->frag_offset > 0) ||
                 (exthdr->ip6e_nxt != IPPROTO_UDP)) )
            {
                /* For non-zero offset frags, we stop decoding after the
                   Frag header. According to RFC 2460, the "Next Header"
                   value may differ from that of the offset zero frag,
                   but only the Next Header of the original frag is used. */
                // check DecodeIP(); we handle frags the same way here
                p->ip6_extension_count++;
                return;
            }
            break;

        case IPPROTO_AH:
            /* Auth Headers work in both IPv4 & IPv6, and their lengths are
               given in 4-octet increments instead of 8-octet increments. */
            hdrlen = sizeof(IP6Extension) + (exthdr->ip6e_len << 2);

            if (hdrlen <= len)
                PushLayer(PROTO_AH, p, pkt, hdrlen);
            break;

        default:
            hdrlen = sizeof(IP6Extension) + (exthdr->ip6e_len << 3);
            break;
    }

    p->ip6_extension_count++;

    if(hdrlen > len)
    {
        DecoderEvent(p, DECODE_IPV6_TRUNCATED_EXT);
        return;
    }

    if ( hdrlen > 0 )
    {
        DecodeIPV6Extensions(*pkt, pkt + hdrlen, len - hdrlen, p);
    }
#ifdef DEBUG_MSGS
    else
    {
        DebugMessage(DEBUG_DECODE, "WARNING - no next ip6 header decoded\n");
    }
#endif
}

void DecodeIPV6Extensions(uint8_t next, const uint8_t *pkt, uint32_t len, Packet *p)
{
    dc.ip6ext++;

    if (p->greh != NULL)
        dc.gre_ipv6ext++;

    /* XXX might this introduce an issue if the "next" field is invalid? */
    p->ip6h->next = next;

    /* See if there are any ip_proto only rules that match */
    fpEvalIpProtoOnlyRules(snort_conf->ip_proto_only_lists, p);
    p->proto_bits |= PROTO_BIT__IP;

    switch(next) {
        case IPPROTO_TCP:
            dc.tcp6++;
            CheckIPv6ExtensionOrder(p);
            DecodeTCP(pkt, len, p);
            return;
        case IPPROTO_UDP:
            dc.udp6++;
            CheckIPv6ExtensionOrder(p);
            DecodeUDP(pkt, len, p);
            return;
        case IPPROTO_ICMPV6:
            dc.icmp6++;
            CheckIPv6ExtensionOrder(p);
            DecodeICMP6(pkt , len, p);
            return;
        case IPPROTO_NONE:
            CheckIPv6ExtensionOrder(p);
            p->dsize = 0;
            return;
        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_FRAGMENT:
        case IPPROTO_AH:
            DecodeIPV6Options(next, pkt, len, p);
            // Anything special to do here?  just return?
            return;
        case IPPROTO_GRE:
            dc.gre++;
            CheckIPv6ExtensionOrder(p);
            DecodeGRE(pkt, len, p);
            return;
        case IPPROTO_IPIP:
            dc.ip6ip4++;
            if ( ScTunnelBypassEnabled(TUNNEL_4IN6) )
                Active_SetTunnelBypass();
            CheckIPv6ExtensionOrder(p);
            DecodeIP(pkt, len, p);
            return;
        case IPPROTO_IPV6:
            dc.ip6ip6++;
            CheckIPv6ExtensionOrder(p);
            DecodeIPV6(pkt, len, p);
            return;
        case IPPROTO_ESP:
            CheckIPv6ExtensionOrder(p);
            if (ScESPDecoding())
                DecodeESP(pkt, len, p);
            return;

        default:
            // There may be valid headers after this unsupported one,
            // need to decode this header, set "next" and continue
            // looping.

            DecoderEvent(p, DECODE_IPV6_BAD_NEXT_HEADER);

            dc.other++;
            p->data = pkt;
            p->dsize = (uint16_t)len;
            break;
    };
}

//--------------------------------------------------------------------
// decode.c::IP6 decoder
//--------------------------------------------------------------------

void DecodeIPV6(const uint8_t *pkt, uint32_t len, Packet *p)
{
    IP6RawHdr *hdr;
    uint32_t payload_len;

    dc.ipv6++;

    if (p->greh != NULL)
        dc.gre_ipv6++;

    hdr = (IP6RawHdr*)pkt;

    if(len < IP6_HDR_LEN)
    {
        if ((p->packet_flags & PKT_UNSURE_ENCAP) == 0)
            DecoderEvent(p, DECODE_IPV6_TRUNCATED);

        goto decodeipv6_fail;
    }

    /* Verify version in IP6 Header agrees */
    if(IPRAW_HDR_VER(hdr) != 6)
    {
        if ((p->packet_flags & PKT_UNSURE_ENCAP) == 0)
            DecoderEvent(p, DECODE_IPV6_IS_NOT);

        goto decodeipv6_fail;
    }

    if (p->family != NO_IP)
    {
        /* Snort currently supports only 2 IP layers. Any more will fail to be
           decoded. */
        if (p->encapsulated)
        {

            DecoderAlertEncapsulated(p, DECODE_IP_MULTIPLE_ENCAPSULATION, pkt, len);
            goto decodeipv6_fail;
        }
        else
        {
            p->encapsulated = 1;
            p->outer_iph = p->iph;
            p->outer_ip_data = p->ip_data;
            p->outer_ip_dsize = p->ip_dsize;
        }
    }
    payload_len = ntohs(hdr->ip6plen) + IP6_HDR_LEN;

    if(payload_len != len)
    {
        if (payload_len > len)
        {
            if ((p->packet_flags & PKT_UNSURE_ENCAP) == 0)
                DecoderEvent(p, DECODE_IPV6_DGRAM_GT_CAPLEN);

            goto decodeipv6_fail;
        }
    }

    /* Teredo packets should always use the 2001:0000::/32 prefix, or in some
       cases the link-local prefix fe80::/64.
       Source: RFC 4380, section 2.6 & section 5.2.1

       Checking the addresses will save us from numerous false positives
       when UDP clients use 3544 as their ephemeral port, or "Deep Teredo
       Inspection" is turned on.

       If we ever start decoding more than 2 layers of IP in a packet, this
       check against p->proto_bits will need to be refactored. */
    if ((p->proto_bits & PROTO_BIT__TEREDO) && (CheckTeredoPrefix(hdr) == 0))
    {
        goto decodeipv6_fail;
    }

    /* lay the IP struct over the raw data */
    // this is ugly but necessary to keep the rest of the code happy
    p->inner_iph = p->iph = (IPHdr *)pkt;

    /* Build Packet structure's version of the IP6 header */
    sfiph_build(p, hdr, AF_INET6);

    /* Remove outer IP options */
    if (p->encapsulated)
    {
        p->ip_options_data = NULL;
        p->ip_options_len = 0;
    }
    p->ip_option_count = 0;

    /* set the real IP length for logging */
    p->actual_ip_len = ntohs(p->ip6h->len);
    p->ip_data = pkt + IP6_HDR_LEN;
    p->ip_dsize = ntohs(p->ip6h->len);

    PushLayer(PROTO_IP6, p, pkt, sizeof(*hdr));

    IPV6MiscTests(p);

    DecodeIPV6Extensions(GET_IPH_PROTO(p), pkt + IP6_HDR_LEN, ntohs(p->ip6h->len), p);
    return;

decodeipv6_fail:
    /* If this was Teredo, back up and treat the packet as normal UDP. */
    if (p->proto_bits & PROTO_BIT__TEREDO)
    {
        dc.ipv6--;
        dc.teredo--;
        p->proto_bits &= ~PROTO_BIT__TEREDO;

        if (p->greh != NULL)
            dc.gre_ipv6--;

        if ( ScTunnelBypassEnabled(TUNNEL_TEREDO) )
            Active_ClearTunnelBypass();
        return;
    }

    dc.discards++;
    dc.ipv6disc++;
}

//--------------------------------------------------------------------
// decode.c::ICMP6
//--------------------------------------------------------------------

void DecodeICMP6(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    if(len < ICMP6_MIN_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "WARNING: Truncated ICMP6 header (%d bytes).\n", len););

        DecoderEvent(p, DECODE_ICMP6_HDR_TRUNC);

        dc.discards++;
        return;
    }

    p->icmp6h = (ICMP6Hdr*)pkt;
    p->icmph = (ICMPHdr*)pkt; /* This is needed for icmp rules */

    /* Do checksums */
    if (ScIcmpChecksums())
    {
        uint16_t csum;

        if(IS_IP4(p))
        {
            csum = in_chksum_icmp((uint16_t *)(p->icmp6h), len);
        }
        /* IPv6 traffic */
        else
        {
            pseudoheader6 ph6;
            COPY4(ph6.sip, p->ip6h->ip_src.ip32);
            COPY4(ph6.dip, p->ip6h->ip_dst.ip32);
            ph6.zero = 0;
            ph6.protocol = GET_IPH_PROTO(p);
            ph6.len = htons((u_short)len);

            csum = in_chksum_icmp6(&ph6, (uint16_t *)(p->icmp6h), len);
        }
        if(csum)
        {
            p->error_flags |= PKT_ERR_CKSUM_ICMP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad ICMP Checksum\n"););
            execIcmpChksmDrop(p);
            dc.invalid_checksums++;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"ICMP Checksum: OK\n"););
        }
    }

    p->dsize = (u_short)(len - ICMP6_MIN_HEADER_LEN);
    p->data = pkt + ICMP6_MIN_HEADER_LEN;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP type: %d   code: %d\n",
                p->icmp6h->type, p->icmp6h->code););

    switch(p->icmp6h->type)
    {
        case ICMP6_ECHO:
        case ICMP6_REPLY:
            if (p->dsize >= sizeof(ICMPHdr::icmp_hun.idseq))
            {
                /* Set data pointer to that of the "echo message" */
                /* add the size of the echo ext to the data
                 * ptr and subtract it from the data size */
                p->dsize -= sizeof(ICMPHdr::icmp_hun.idseq);
                p->data += sizeof(ICMPHdr::icmp_hun.idseq);

                if ( p->ip6h->ip_dst.ip.u6_addr8[0] == IP6_MULTICAST )
                    DecoderEvent(p, DECODE_ICMP6_DST_MULTICAST);

                PushLayer(PROTO_ICMP6, p, pkt, ICMP_NORMAL_LEN);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "WARNING: Truncated ICMP Echo header (%d bytes).\n", len););

                DecoderEvent(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                p->icmp6h = NULL;
                dc.discards++;
                dc.icmpdisc++;
                return;
            }
            break;

        case ICMP6_BIG:
            if (p->dsize >= sizeof(ICMP6TooBig))
            {
                ICMP6TooBig *too_big = (ICMP6TooBig *)pkt;
                /* Set data pointer past MTU */
                p->data += 4;
                p->dsize -= 4;

                if (ntohl(too_big->mtu) < 1280)
                {
                    DecoderEvent(p, DECODE_ICMPV6_TOO_BIG_BAD_MTU);
                }

                PushLayer(PROTO_ICMP6, p, pkt, ICMP_NORMAL_LEN);
                DecodeICMPEmbeddedIP6(p->data, p->dsize, p);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "WARNING: Truncated ICMP header (%d bytes).\n", len););

                DecoderEvent(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                p->icmp6h = NULL;
                dc.discards++;
                dc.icmpdisc++;
                return;
            }
            break;

        case ICMP6_TIME:
        case ICMP6_PARAMS:
        case ICMP6_UNREACH:
            if (p->dsize >= 4)
            {
                /* Set data pointer past the 'unused/mtu/pointer block */
                p->data += 4;
                p->dsize -= 4;

                if (p->icmp6h->type == ICMP6_UNREACH)
                {
                    if (p->icmp6h->code == 2)
                    {
                        DecoderEvent(p, DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE);
                    }
                    else if (p->icmp6h->code > 6)
                    {
                        DecoderEvent(p, DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE);
                    }
                }

                PushLayer(PROTO_ICMP6, p, pkt, ICMP_NORMAL_LEN);
                DecodeICMPEmbeddedIP6(p->data, p->dsize, p);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "WARNING: Truncated ICMP header (%d bytes).\n", len););

                DecoderEvent(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                p->icmp6h = NULL;
                dc.discards++;
                dc.icmpdisc++;
                return;
            }
            break;

        case ICMP6_ADVERTISEMENT:
            if (p->dsize >= (sizeof(ICMP6RouterAdvertisement) - ICMP6_MIN_HEADER_LEN))
            {
                ICMP6RouterAdvertisement *ra = (ICMP6RouterAdvertisement *)pkt;
                if (p->icmp6h->code != 0)
                {
                    DecoderEvent(p, DECODE_ICMPV6_ADVERT_BAD_CODE);
                }
                if (ntohl(ra->reachable_time) > 3600000)
                {
                    DecoderEvent(p, DECODE_ICMPV6_ADVERT_BAD_REACHABLE);
                }
                PushLayer(PROTO_ICMP6, p, pkt, ICMP_HEADER_LEN);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "WARNING: Truncated ICMP header (%d bytes).\n", len););

                DecoderEvent(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                p->icmp6h = NULL;
                dc.discards++;
                dc.icmpdisc++;
                return;
            }
            break;

        case ICMP6_SOLICITATION:
            if (p->dsize >= (sizeof(ICMP6RouterSolicitation) - ICMP6_MIN_HEADER_LEN))
            {
                ICMP6RouterSolicitation *rs = (ICMP6RouterSolicitation *)pkt;
                if (rs->code != 0)
                {
                    DecoderEvent(p, DECODE_ICMPV6_SOLICITATION_BAD_CODE);
                }
                if (ntohl(rs->reserved) != 0)
                {
                    DecoderEvent(p, DECODE_ICMPV6_SOLICITATION_BAD_RESERVED);
                }
                PushLayer(PROTO_ICMP6, p, pkt, ICMP_HEADER_LEN);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "WARNING: Truncated ICMP header (%d bytes).\n", len););

                DecoderEvent(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                p->icmp6h = NULL;
                dc.discards++;
                dc.icmpdisc++;
                return;
            }
            break;

        case ICMP6_NODE_INFO_QUERY:
        case ICMP6_NODE_INFO_RESPONSE:
            if (p->dsize >= (sizeof(ICMP6NodeInfo) - ICMP6_MIN_HEADER_LEN))
            {
                ICMP6NodeInfo *ni = (ICMP6NodeInfo *)pkt;
                if (ni->code > 2)
                {
                    DecoderEvent(p, DECODE_ICMPV6_NODE_INFO_BAD_CODE);
                }
                /* TODO: Add alert for INFO Response, code == 1 || code == 2)
                 * and there is data.
                 */
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "WARNING: Truncated ICMP header (%d bytes).\n", len););

                DecoderEvent(p, DECODE_ICMP_DGRAM_LT_ICMPHDR);

                p->icmph = NULL;
                p->icmp6h = NULL;
                dc.discards++;
                dc.icmpdisc++;
                return;
            }
            break;

        default:
            DecoderEvent(p, DECODE_ICMP6_TYPE_OTHER);

            PushLayer(PROTO_ICMP6, p, pkt, ICMP_HEADER_LEN);
            break;
    }

    p->proto_bits |= PROTO_BIT__ICMP;
    p->proto_bits &= ~(PROTO_BIT__UDP | PROTO_BIT__TCP);
}

/*
 * Function: DecodeICMPEmbeddedIP6(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the ICMP embedded IP6 header + payload
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to dummy packet decode struct
 *
 * Returns: void function
 */
void DecodeICMPEmbeddedIP6(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    uint16_t orig_frag_offset;

    /* lay the IP struct over the raw data */
    IP6RawHdr* hdr = (IP6RawHdr*)pkt;
    dc.embdip++;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "DecodeICMPEmbeddedIP6: ip header"
                    " starts at: %p, length is %lu\n", hdr,
                    (unsigned long) len););

    /* do a little validation */
    if ( len < IP6_HDR_LEN )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP6: IP short header (%d bytes)\n", len););

        DecoderEvent(p, DECODE_ICMP_ORIG_IP_TRUNCATED);

        dc.discards++;
        return;
    }

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if(IPRAW_HDR_VER(hdr) != 6)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP: not IPv6 datagram ([ver: 0x%x][len: 0x%x])\n",
            IPRAW_HDR_VER(hdr), len););

        DecoderEvent(p, DECODE_ICMP_ORIG_IP_VER_MISMATCH);

        dc.discards++;
        return;
    }

    if ( len < IP6_HDR_LEN )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP6: IP6 len (%d bytes) < IP6 hdr len (%d bytes), packet discarded\n",
            len, IP6_HDR_LEN););

        DecoderEvent(p, DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP);

        dc.discards++;
        return;
    }
    sfiph_orig_build(p, pkt, AF_INET6);

    orig_frag_offset = ntohs(GET_ORIG_IPH_OFF(p));
    orig_frag_offset &= 0x1FFF;

    // XXX NOT YET IMPLEMENTED - fragments inside ICMP payload

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP6 Unreachable IP6 header length: "
                            "%lu\n", (unsigned long)IP6_HDR_LEN););

    switch(GET_ORIG_IPH_PROTO(p))
    {
        case IPPROTO_TCP: /* decode the interesting part of the header */
            p->orig_tcph = (TCPHdr *)(pkt + IP6_HDR_LEN);

            /* stuff more data into the printout data struct */
            p->orig_sp = ntohs(p->orig_tcph->th_sport);
            p->orig_dp = ntohs(p->orig_tcph->th_dport);

            break;

        case IPPROTO_UDP:
            p->orig_udph = (UDPHdr *)(pkt + IP6_HDR_LEN);

            /* fill in the printout data structs */
            p->orig_sp = ntohs(p->orig_udph->uh_sport);
            p->orig_dp = ntohs(p->orig_udph->uh_dport);

            break;

        case IPPROTO_ICMP:
            p->orig_icmph = (ICMPHdr *)(pkt + IP6_HDR_LEN);
            break;
    }

    return;
}

//--------------------------------------------------------------------
// decode.c::Teredo
//--------------------------------------------------------------------

/* Function: DecodeTeredo(uint8_t *, uint32_t, Packet *)
 *
 * Teredo is IPv6 layered over UDP, with optional "indicators" in between.
 * Decode these (if present) and go to DecodeIPv6.
 *
 */

void DecodeTeredo(const uint8_t *pkt, uint32_t len, Packet *p)
{
    if (len < TEREDO_MIN_LEN)
        return;

    /* Decode indicators. If both are present, Auth always comes before Origin. */
    if (ntohs(*(uint16_t *)pkt) == TEREDO_INDICATOR_AUTH)
    {
        uint8_t client_id_length, auth_data_length;

        if (len < TEREDO_INDICATOR_AUTH_MIN_LEN)
            return;

        client_id_length = *(pkt + 2);
        auth_data_length = *(pkt + 3);

        if (len < (uint32_t)(TEREDO_INDICATOR_AUTH_MIN_LEN + client_id_length + auth_data_length))
            return;

        pkt += (TEREDO_INDICATOR_AUTH_MIN_LEN + client_id_length + auth_data_length);
        len -= (TEREDO_INDICATOR_AUTH_MIN_LEN + client_id_length + auth_data_length);
    }

    if (ntohs(*(uint16_t *)pkt) == TEREDO_INDICATOR_ORIGIN)
    {
        if (len < TEREDO_INDICATOR_ORIGIN_LEN)
            return;

        pkt += TEREDO_INDICATOR_ORIGIN_LEN;
        len -= TEREDO_INDICATOR_ORIGIN_LEN;
    }

    /* If this is an IPv6 datagram, the first 4 bits will be the number 6. */
    if (( (*pkt & 0xF0) >> 4) == 6)
    {
        p->proto_bits |= PROTO_BIT__TEREDO;
        dc.teredo++;

        if ( ScTunnelBypassEnabled(TUNNEL_TEREDO) )
            Active_SetTunnelBypass();

        if (ScDeepTeredoInspection() && (p->sp != TEREDO_PORT) && (p->dp != TEREDO_PORT))
            p->packet_flags |= PKT_UNSURE_ENCAP;

        DecodeIPV6(pkt, len, p);

        p->packet_flags &= ~PKT_UNSURE_ENCAP;
    }

    /* Otherwise, we treat this as normal UDP traffic. */
    return;
}

//--------------------------------------------------------------------
// decode.c::ESP
//--------------------------------------------------------------------

/* Function: DecodeAH
 *
 * Purpose: Decode Authentication Header
 *
 * NOTE: This is for IPv4 Auth Headers, we leave IPv6 to do its own
 * work.
 *
 */
void DecodeAH(const uint8_t *pkt, uint32_t len, Packet *p)
{
    IP6Extension *ah = (IP6Extension *)pkt;
    uint8_t extlen = sizeof(*ah) + (ah->ip6e_len << 2);

    if (extlen > len)
    {
        return;
    }

    PushLayer(PROTO_AH, p, pkt, extlen);

    DecodeIPv4Proto(ah->ip6e_nxt, pkt+extlen, len-extlen, p);
}

/*
 * Function: DecodeESP(const uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Attempt to decode Encapsulated Security Payload.
 *          The contents are probably encrypted, but ESP is sometimes used
 *          with "null" encryption, solely for Authentication.
 *          This is more of a heuristic -- there is no ESP field that specifies
 *          the encryption type (or lack thereof).
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => ptr to the Packet struct being filled out
 *
 * Returns: void function
 */
void DecodeESP(const uint8_t *pkt, uint32_t len, Packet *p)
{
    const uint8_t *esp_payload;
    uint8_t next_header;
    uint8_t pad_length;
    uint8_t save_layer = p->next_layer;

    /* The ESP header contains a crypto Initialization Vector (IV) and
       a sequence number. Skip these. */
    if (len < (ESP_HEADER_LEN + ESP_AUTH_DATA_LEN + ESP_TRAILER_LEN))
    {
        /* Truncated ESP traffic. Bail out here and inspect the rest as payload. */
        DecoderEvent(p, DECODE_ESP_HEADER_TRUNC);
        p->data = pkt;
        p->dsize = (uint16_t) len;
        return;
    }
    esp_payload = pkt + ESP_HEADER_LEN;

    /* The Authentication Data at the end of the packet is variable-length.
       RFC 2406 says that Encryption and Authentication algorithms MUST NOT
       both be NULL, so we assume NULL Encryption and some other Authentication.

       The mandatory algorithms for Authentication are HMAC-MD5-96 and
       HMAC-SHA-1-96, so we assume a 12-byte authentication data at the end. */
    len -= (ESP_HEADER_LEN + ESP_AUTH_DATA_LEN + ESP_TRAILER_LEN);

    pad_length = *(esp_payload + len);
    next_header = *(esp_payload + len + 1);

    /* Adjust the packet length to account for the padding.
       If the padding length is too big, this is probably encrypted traffic. */
    if (pad_length < len)
    {
        len -= (pad_length);
    }
    else
    {
        p->packet_flags |= PKT_TRUST;
        p->data = esp_payload;
        p->dsize = (u_short) len;
        return;
    }

    /* Attempt to decode the inner payload.
       There is a small chance that an encrypted next_header would become a
       different valid next_header. The PKT_UNSURE_ENCAP flag tells the next
       decoder stage to silently ignore invalid headers. */

    p->packet_flags |= PKT_UNSURE_ENCAP;
    switch (next_header)
    {
       case IPPROTO_IPIP:
            DecodeIP(esp_payload, len, p);
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            break;

        case IPPROTO_IPV6:
            DecodeIPV6(esp_payload, len, p);
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            break;

       case IPPROTO_TCP:
            dc.tcp++;
            DecodeTCP(esp_payload, len, p);
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            break;

        case IPPROTO_UDP:
            dc.udp++;
            DecodeUDP(esp_payload, len, p);
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            break;

        case IPPROTO_ICMP:
            dc.icmp++;
            DecodeICMP(esp_payload, len, p);
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            break;

        case IPPROTO_GRE:
            dc.gre++;
            DecodeGRE(esp_payload, len, p);
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            break;

        default:
            /* If we didn't get a valid next_header, this packet is probably
               encrypted. Start data here and treat it as an IP datagram. */
            p->data = esp_payload;
            p->dsize = (u_short) len;
            p->packet_flags &= ~PKT_UNSURE_ENCAP;
            p->packet_flags |= PKT_TRUST;
            return;
    }

    /* If no protocol was added to the stack, than we assume its'
     * encrypted. */
    if (save_layer == p->next_layer)
        p->packet_flags |= PKT_TRUST;
}

//--------------------------------------------------------------------
// decode.c::ERSPAN
//--------------------------------------------------------------------

/*
 * Function: DecodeERSPANType2(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode Encapsulated Remote Switch Packet Analysis Type 2
 *          This will decode ERSPAN Type 2 Headers
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 *
 */
void DecodeERSPANType2(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    uint32_t hlen = sizeof(ERSpanType2Hdr);
    uint32_t payload_len;
    ERSpanType2Hdr *erSpan2Hdr = (ERSpanType2Hdr *)pkt;

    if (len < sizeof(ERSpanType2Hdr))
    {
        DecoderAlertEncapsulated(p, DECODE_ERSPAN2_DGRAM_LT_HDR, pkt, len);
        return;
    }

    if (p->encapsulated)
    {
        /* discard packet - multiple encapsulation */
        /* not sure if this is ever used but I am assuming it is not */
        DecoderAlertEncapsulated(p, DECODE_IP_MULTIPLE_ENCAPSULATION, pkt, len);
        return;
    }

    /* Check that this is in fact ERSpan Type 2.
     */
    if (ERSPAN_VERSION(erSpan2Hdr) != 0x01) /* Type 2 == version 0x01 */
    {
        DecoderAlertEncapsulated(p, DECODE_ERSPAN_HDR_VERSION_MISMATCH, pkt, len);
        return;
    }

    PushLayer(PROTO_ERSPAN, p, pkt, hlen);
    payload_len = len - hlen;

    DecodeTransBridging(pkt + hlen, payload_len, p);
}

/*
 * Function: DecodeERSPANType3(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode Encapsulated Remote Switch Packet Analysis Type 3
 *          This will decode ERSPAN Type 3 Headers
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 *
 */
void DecodeERSPANType3(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    uint32_t hlen = sizeof(ERSpanType3Hdr);
    uint32_t payload_len;
    ERSpanType3Hdr *erSpan3Hdr = (ERSpanType3Hdr *)pkt;

    if (len < sizeof(ERSpanType3Hdr))
    {
        DecoderAlertEncapsulated(p, DECODE_ERSPAN3_DGRAM_LT_HDR, pkt, len);
        return;
    }

    if (p->encapsulated)
    {
        /* discard packet - multiple encapsulation */
        /* not sure if this is ever used but I am assuming it is not */
        DecoderAlertEncapsulated(p, DECODE_IP_MULTIPLE_ENCAPSULATION, pkt, len);
        return;
    }

    /* Check that this is in fact ERSpan Type 3.
     */
    if (ERSPAN_VERSION(erSpan3Hdr) != 0x02) /* Type 3 == version 0x02 */
    {
        DecoderAlertEncapsulated(p, DECODE_ERSPAN_HDR_VERSION_MISMATCH, pkt, len);
        return;
    }

    PushLayer(PROTO_ERSPAN, p, pkt, hlen);
    payload_len = len - hlen;

    DecodeTransBridging(pkt + hlen, payload_len, p);
}

//--------------------------------------------------------------------
// decode.c::GRE
//--------------------------------------------------------------------

/*
 * Function: DecodeGRE(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode Generic Routing Encapsulation Protocol
 *          This will decode normal GRE and PPTP GRE.
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 *
 * Notes: see RFCs 1701, 2784 and 2637
 */
void DecodeGRE(const uint8_t *pkt, const uint32_t len, Packet *p)
{
    uint32_t hlen;    /* GRE header length */
    uint32_t payload_len;

    if (len < GRE_HEADER_LEN)
    {
        DecoderAlertEncapsulated(p, DECODE_GRE_DGRAM_LT_GREHDR, pkt, len);
        return;
    }

    if (p->encapsulated)
    {
        /* discard packet - multiple GRE encapsulation */
        /* not sure if this is ever used but I am assuming it is not */
        DecoderAlertEncapsulated(p, DECODE_IP_MULTIPLE_ENCAPSULATION, pkt, len);
        return;
    }

    /* Note: Since GRE doesn't have a field to indicate header length and
     * can contain a few options, we need to walk through the header to
     * figure out the length
     */

    p->greh = (GREHdr *)pkt;
    hlen = GRE_HEADER_LEN;

    switch (GRE_VERSION(p->greh))
    {
        case 0x00:
            /* these must not be set */
            if (GRE_RECUR(p->greh) || GRE_FLAGS(p->greh))
            {
                DecoderAlertEncapsulated(p, DECODE_GRE_INVALID_HEADER, pkt, len);
                return;
            }

            if (GRE_CHKSUM(p->greh) || GRE_ROUTE(p->greh))
                hlen += GRE_CHKSUM_LEN + GRE_OFFSET_LEN;

            if (GRE_KEY(p->greh))
                hlen += GRE_KEY_LEN;

            if (GRE_SEQ(p->greh))
                hlen += GRE_SEQ_LEN;

            /* if this flag is set, we need to walk through all of the
             * Source Route Entries */
            if (GRE_ROUTE(p->greh))
            {
                uint16_t sre_addrfamily;
                uint8_t sre_offset;
                uint8_t sre_length;
                const uint8_t *sre_ptr;

                sre_ptr = pkt + hlen;

                while (1)
                {
                    hlen += GRE_SRE_HEADER_LEN;
                    if (hlen > len)
                        break;

                    sre_addrfamily = ntohs(*((uint16_t *)sre_ptr));
                    sre_ptr += sizeof(sre_addrfamily);

                    sre_offset = *((uint8_t *)sre_ptr);
                    sre_ptr += sizeof(sre_offset);

                    sre_length = *((uint8_t *)sre_ptr);
                    sre_ptr += sizeof(sre_length);

                    if ((sre_addrfamily == 0) && (sre_length == 0))
                        break;

                    hlen += sre_length;
                    sre_ptr += sre_length;
                }
            }

            break;

        /* PPTP */
        case 0x01:
            /* these flags should never be present */
            if (GRE_CHKSUM(p->greh) || GRE_ROUTE(p->greh) || GRE_SSR(p->greh) ||
                GRE_RECUR(p->greh) || GRE_V1_FLAGS(p->greh))
            {
                DecoderAlertEncapsulated(p, DECODE_GRE_V1_INVALID_HEADER, pkt, len);
                return;
            }

            /* protocol must be 0x880B - PPP */
            if (GRE_PROTO(p->greh) != GRE_TYPE_PPP)
            {
                DecoderAlertEncapsulated(p, DECODE_GRE_V1_INVALID_HEADER, pkt, len);
                return;
            }

            /* this flag should always be present */
            if (!(GRE_KEY(p->greh)))
            {
                DecoderAlertEncapsulated(p, DECODE_GRE_V1_INVALID_HEADER, pkt, len);
                return;
            }

            hlen += GRE_KEY_LEN;

            if (GRE_SEQ(p->greh))
                hlen += GRE_SEQ_LEN;

            if (GRE_V1_ACK(p->greh))
                hlen += GRE_V1_ACK_LEN;

            break;

        default:
            DecoderAlertEncapsulated(p, DECODE_GRE_INVALID_VERSION, pkt, len);
            return;
    }

    if (hlen > len)
    {
        DecoderAlertEncapsulated(p, DECODE_GRE_DGRAM_LT_GREHDR, pkt, len);
        return;
    }

    PushLayer(PROTO_GRE, p, pkt, hlen);
    payload_len = len - hlen;

    /* Send to next protocol decoder */
    /* As described in RFC 2784 the possible protocols are listed in
     * RFC 1700 under "ETHER TYPES"
     * See also "Current List of Protocol Types" in RFC 1701
     */
    switch (GRE_PROTO(p->greh))
    {
        case ETHERNET_TYPE_IP:
            DecodeIP(pkt + hlen, payload_len, p);
            return;

        case GRE_TYPE_TRANS_BRIDGING:
            DecodeTransBridging(pkt + hlen, payload_len, p);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            /* clear outer IP headers */
            p->iph = NULL;
            p->family = NO_IP;
            DecodeARP(pkt + hlen, payload_len, p);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(pkt + hlen, payload_len, p);
            return;

        case GRE_TYPE_PPP:
            DecodePppPktEncapsulated(pkt + hlen, payload_len, p);
            return;

        case ETHERNET_TYPE_ERSPAN_TYPE2:
            DecodeERSPANType2(pkt + hlen, payload_len, p);
            return;

        case ETHERNET_TYPE_ERSPAN_TYPE3:
            DecodeERSPANType3(pkt + hlen, payload_len, p);
            return;

#ifndef NO_NON_ETHER_DECODER
        case ETHERNET_TYPE_IPX:
            DecodeIPX(pkt + hlen, payload_len, p);
            return;
#endif

        case ETHERNET_TYPE_LOOP:
            DecodeEthLoopback(pkt + hlen, payload_len, p);
            return;

        /* not sure if this occurs, but 802.1q is an Ether type */
        case ETHERNET_TYPE_8021Q:
            DecodeVlan(pkt + hlen, payload_len, p);
            return;

        default:
            // TBD add decoder drop event for unknown gre/eth type
            dc.other++;
            p->data = pkt + hlen;
            p->dsize = (uint16_t)payload_len;
            return;
    }
}

//--------------------------------------------------------------------
// decode.c::GTP
//--------------------------------------------------------------------

/* Function: DecodeGTP(uint8_t *, uint32_t, Packet *)
 *
 * GTP (GPRS Tunneling Protocol) is layered over UDP.
 * Decode these (if present) and go to DecodeIPv6/DecodeIP.
 *
 */

void DecodeGTP(const uint8_t *pkt, uint32_t len, Packet *p)
{
    uint32_t header_len;
    uint8_t  next_hdr_type;
    uint8_t  version;
    uint8_t  ip_ver;
    GTPHdr *hdr;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Start GTP decoding.\n"););

    hdr = (GTPHdr *) pkt;

    if (p->GTPencapsulated)
    {
        DecoderAlertEncapsulated(p, DECODE_GTP_MULTIPLE_ENCAPSULATION, pkt, len);
        return;
    }
    else
    {
        p->GTPencapsulated = 1;
    }
    /*Check the length*/
    if (len < GTP_MIN_LEN)
       return;
    /* We only care about PDU*/
    if ( hdr->type != 255)
       return;
    /*Check whether this is GTP or GTP', Exit if GTP'*/
    if (!(hdr->flag & 0x10))
       return;

    /*The first 3 bits are version number*/
    version = (hdr->flag & 0xE0) >> 5;
    switch (version)
    {
    case 0: /*GTP v0*/
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "GTP v0 packets.\n"););

        header_len = GTP_V0_HEADER_LEN;
        /*Check header fields*/
        if (len < header_len)
        {
            DecoderEvent(p, DECODE_GTP_BAD_LEN);
            return;
        }

        p->proto_bits |= PROTO_BIT__GTP;

        /*Check the length field. */
        if (len != ((unsigned int)ntohs(hdr->length) + header_len))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Calculated length %d != %d in header.\n",
                    len - header_len, ntohs(hdr->length)););
            DecoderEvent(p, DECODE_GTP_BAD_LEN);
            return;
        }

        break;
    case 1: /*GTP v1*/
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "GTP v1 packets.\n"););

        /*Check the length based on optional fields and extension header*/
        if (hdr->flag & 0x07)
        {

            header_len = GTP_V1_HEADER_LEN;

            /*Check optional fields*/
            if (len < header_len)
            {
                DecoderEvent(p, DECODE_GTP_BAD_LEN);
                return;
            }
            next_hdr_type = *(pkt + header_len - 1);

            /*Check extension headers*/
            while (next_hdr_type)
            {
                uint16_t ext_hdr_len;
                /*check length before reading data*/
                if (len < header_len + 4)
                {
                    DecoderEvent(p, DECODE_GTP_BAD_LEN);
                    return;
                }

                ext_hdr_len = *(pkt + header_len);

                if (!ext_hdr_len)
                {
                    DecoderEvent(p, DECODE_GTP_BAD_LEN);
                    return;
                }
                /*Extension header length is a unit of 4 octets*/
                header_len += ext_hdr_len * 4;

                /*check length before reading data*/
                if (len < header_len)
                {
                    DecoderEvent(p, DECODE_GTP_BAD_LEN);
                    return;
                }
                next_hdr_type = *(pkt + header_len - 1);
            }
        }
        else
            header_len = GTP_MIN_LEN;

        p->proto_bits |= PROTO_BIT__GTP;

        /*Check the length field. */
        if (len != ((unsigned int)ntohs(hdr->length) + GTP_MIN_LEN))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Calculated length %d != %d in header.\n",
                    len - GTP_MIN_LEN, ntohs(hdr->length)););
            DecoderEvent(p, DECODE_GTP_BAD_LEN);
            return;
        }

        break;
    default:
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Unknown protocol version.\n"););
        return;

    }

    PushLayer(PROTO_GTP, p, pkt, header_len);

    if ( ScTunnelBypassEnabled(TUNNEL_GTP) )
        Active_SetTunnelBypass();

    len -=  header_len;
    if (len > 0)
    {
        ip_ver = *(pkt+header_len) & 0xF0;
        if (ip_ver == 0x40)
            DecodeIP(pkt+header_len, len, p);
        else if (ip_ver == 0x60)
            DecodeIPV6(pkt+header_len, len, p);
        p->packet_flags &= ~PKT_UNSURE_ENCAP;
    }

}

//--------------------------------------------------------------------
// decode.c::UDP
//--------------------------------------------------------------------

/* UDP-layer decoder alerts */
static inline void UDPMiscTests(Packet *p)
{
    {
        if (p->dsize > 4000)
            DecoderEvent(p, DECODE_UDP_LARGE_PACKET);
    }

    {
        if (p->sp == 0 || p->dp == 0)
            DecoderEvent(p, DECODE_UDP_PORT_ZERO);
    }
}

/*
 * Function: DecodeUDP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the UDP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
static inline void PopUdp (Packet* p)
{
    p->udph = p->outer_udph;
    p->outer_udph = NULL;
    dc.discards++;
    dc.udisc++;

    // required for detect.c to short-circuit preprocessing
    if ( !p->dsize )
        p->dsize = p->ip_dsize;
}

void DecodeUDP(const uint8_t * pkt, const uint32_t len, Packet * p)
{
    uint16_t uhlen;
    u_char fragmented_udp_flag = 0;

    if (p->proto_bits & (PROTO_BIT__TEREDO | PROTO_BIT__GTP))
        p->outer_udph = p->udph;

    if(len < sizeof(UDPHdr))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                "Truncated UDP header (%d bytes)\n", len););

        DecoderEvent(p, DECODE_UDP_DGRAM_LT_UDPHDR);

        PopUdp(p);
        return;
    }

    /* set the ptr to the start of the UDP header */
    p->inner_udph = p->udph = (UDPHdr *) pkt;

    if (!p->frag_flag)
    {
        uhlen = ntohs(p->udph->uh_len);
    }
    else
    {
        if(IS_IP6(p))
        {
            uint16_t ip_len = ntohs(GET_IPH_LEN(p));
            /* subtract the distance from udp header to 1st ip6 extension */
            /* This gives the length of the UDP "payload", when fragmented */
            uhlen = ip_len - ((u_char *)p->udph - (u_char *)p->ip6_extensions[0].data);
        }
        else
        {
            uint16_t ip_len = ntohs(GET_IPH_LEN(p));
            /* Don't forget, IP_HLEN is a word - multiply x 4 */
            uhlen = ip_len - (GET_IPH_HLEN(p) * 4 );
        }
        fragmented_udp_flag = 1;
    }

    /* verify that the header len is a valid value */
    if(uhlen < UDP_HEADER_LEN)
    {
        DecoderEvent(p, DECODE_UDP_DGRAM_INVALID_LENGTH);

        PopUdp(p);
        return;
    }

    /* make sure there are enough bytes as designated by length field */
    if(uhlen > len)
    {
        DecoderEvent(p, DECODE_UDP_DGRAM_SHORT_PACKET);

        PopUdp(p);
        return;
    }
    else if(uhlen < len)
    {
        DecoderEvent(p, DECODE_UDP_DGRAM_LONG_PACKET);

        PopUdp(p);
        return;
    }

    if (ScUdpChecksums())
    {
        /* look at the UDP checksum to make sure we've got a good packet */
        uint16_t csum;
        if(IS_IP4(p))
        {
            pseudoheader ph;
            ph.sip = *p->ip4h->ip_src.ip32;
            ph.dip = *p->ip4h->ip_dst.ip32;
            ph.zero = 0;
            ph.protocol = GET_IPH_PROTO(p);
            ph.len = p->udph->uh_len;
            /* Don't do checksum calculation if
             * 1) Fragmented, OR
             * 2) UDP header chksum value is 0.
             */
            if( !fragmented_udp_flag && p->udph->uh_chk )
            {
                csum = in_chksum_udp(&ph,
                    (uint16_t *)(p->udph), uhlen);
            }
            else
            {
                csum = 0;
            }
        }
        else
        {
            pseudoheader6 ph6;
            COPY4(ph6.sip, p->ip6h->ip_src.ip32);
            COPY4(ph6.dip, p->ip6h->ip_dst.ip32);
            ph6.zero = 0;
            ph6.protocol = GET_IPH_PROTO(p);
            ph6.len = htons((u_short)len);

            /* Alert on checksum value 0 for ipv6 packets */
            if(!p->udph->uh_chk)
            {
                csum = 1;
                DecoderEvent(p, DECODE_UDP_IPV6_ZERO_CHECKSUM);
            }
            /* Don't do checksum calculation if
             * 1) Fragmented
             * (UDP checksum is not optional in IP6)
             */
            else if( !fragmented_udp_flag )
            {
                csum = in_chksum_udp6(&ph6,
                    (uint16_t *)(p->udph), uhlen);
            }
            else
            {
                csum = 0;
            }
        }
        if(csum)
        {
            /* Don't drop the packet if this was ESP or Teredo.
               Just stop decoding. */
            if (p->packet_flags & PKT_UNSURE_ENCAP)
            {
                PopUdp(p);
                return;
            }

            p->error_flags |= PKT_ERR_CKSUM_UDP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad UDP Checksum\n"););
            execUdpChksmDrop(p);
            dc.invalid_checksums++;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "UDP Checksum: OK\n"););
        }
    }

    /* fill in the printout data structs */
    p->sp = ntohs(p->udph->uh_sport);
    p->dp = ntohs(p->udph->uh_dport);

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "UDP header starts at: %p\n", p->udph););

    PushLayer(PROTO_UDP, p, pkt, sizeof(*p->udph));

    p->data = (uint8_t *) (pkt + UDP_HEADER_LEN);

    /* length was validated up above */
    p->dsize = uhlen - UDP_HEADER_LEN;

    p->proto_bits |= PROTO_BIT__UDP;

    /*  Drop packet if we ignore this port  */
    if (ScIgnoreUdpPort(p->sp) || ScIgnoreUdpPort(p->dp))
    {
        /*  Ignore all preprocessors for this packet */
        p->packet_flags |= PKT_IGNORE;
        return;
    }

    UDPMiscTests(p);

    if (p->sp == TEREDO_PORT ||
        p->dp == TEREDO_PORT ||
        ScDeepTeredoInspection())
    {
        if ( !p->frag_flag )
            DecodeTeredo(pkt + sizeof(UDPHdr), len - sizeof(UDPHdr), p);
    }
    if (ScGTPDecoding() &&
         (ScIsGTPPort(p->sp)||ScIsGTPPort(p->dp)))
    {
        if ( !p->frag_flag )
            DecodeGTP(pkt + sizeof(UDPHdr), len - sizeof(UDPHdr), p);
    }

}

//--------------------------------------------------------------------
// decode.c::TCP
//--------------------------------------------------------------------

/* TCP-layer decoder alerts */
static inline void TCPMiscTests(Packet *p)
{
    {
        if ( ((p->tcph->th_flags & TH_NORESERVED) == TH_SYN ) &&
             (p->tcph->th_seq == htonl(674711609)) )
            DecoderEvent(p, DECODE_TCP_SHAFT_SYNFLOOD);
    }

    {
        if (p->sp == 0 || p->dp == 0)
            DecoderEvent(p, DECODE_TCP_PORT_ZERO);
    }
}

/*
 * Function: DecodeTCP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the TCP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => Pointer to packet decode struct
 *
 * Returns: void function
 */
void DecodeTCP(const uint8_t * pkt, const uint32_t len, Packet * p)
{
    uint32_t hlen;            /* TCP header length */

    if(len < TCP_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "TCP packet (len = %d) cannot contain " "20 byte header\n", len););

        DecoderEvent(p, DECODE_TCP_DGRAM_LT_TCPHDR);

        p->tcph = NULL;
        dc.discards++;
        dc.tdisc++;

        return;
    }

    /* lay TCP on top of the data cause there is enough of it! */
    p->tcph = (TCPHdr *) pkt;

    /* multiply the payload offset value by 4 */
    hlen = TCP_OFFSET(p->tcph) << 2;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "TCP th_off is %d, passed len is %lu\n",
                TCP_OFFSET(p->tcph), (unsigned long)len););

    if(hlen < TCP_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "TCP Data Offset (%d) < hlen (%d) \n",
            TCP_OFFSET(p->tcph), hlen););

        DecoderEvent(p, DECODE_TCP_INVALID_OFFSET);

        p->tcph = NULL;
        dc.discards++;
        dc.tdisc++;

        return;
    }

    if(hlen > len)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "TCP Data Offset(%d) < longer than payload(%d)!\n",
            TCP_OFFSET(p->tcph) << 2, len););

        DecoderEvent(p, DECODE_TCP_LARGE_OFFSET);

        p->tcph = NULL;
        dc.discards++;
        dc.tdisc++;

        return;
    }

    /* Checksum code moved in front of the other decoder alerts.
       If it's a bad checksum (maybe due to encrypted ESP traffic), the other
       alerts could be false positives. */
    if (ScTcpChecksums())
    {
        uint16_t csum;
        if(IS_IP4(p))
        {
            pseudoheader ph;
            ph.sip = *p->ip4h->ip_src.ip32;
            ph.dip = *p->ip4h->ip_dst.ip32;
            /* setup the pseudo header for checksum calculation */
            ph.zero = 0;
            ph.protocol = GET_IPH_PROTO(p);
            ph.len = htons((u_short)len);

            /* if we're being "stateless" we probably don't care about the TCP
             * checksum, but it's not bad to keep around for shits and giggles */
            /* calculate the checksum */
            csum = in_chksum_tcp(&ph, (uint16_t *)(p->tcph), len);
        }
        /* IPv6 traffic */
        else
        {
            pseudoheader6 ph6;
            COPY4(ph6.sip, p->ip6h->ip_src.ip32);
            COPY4(ph6.dip, p->ip6h->ip_dst.ip32);
            ph6.zero = 0;
            ph6.protocol = GET_IPH_PROTO(p);
            ph6.len = htons((u_short)len);

            csum = in_chksum_tcp6(&ph6, (uint16_t *)(p->tcph), len);
        }

        if(csum)
        {
            /* Don't drop the packet if this is encapuslated in Teredo or ESP.
               Just get rid of the TCP header and stop decoding. */
            if (p->packet_flags & PKT_UNSURE_ENCAP)
            {
                p->tcph = NULL;
                return;
            }

            p->error_flags |= PKT_ERR_CKSUM_TCP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad TCP checksum\n",
                                    "0x%x versus 0x%x\n", csum,
                                    ntohs(p->tcph->th_sum)););

            execTcpChksmDrop(p);
            dc.invalid_checksums++;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"TCP Checksum: OK\n"););
        }
    }

    {
        if(TCP_ISFLAGSET(p->tcph, (TH_FIN|TH_PUSH|TH_URG)))
        {
            if(TCP_ISFLAGSET(p->tcph, (TH_SYN|TH_ACK|TH_RST)))
            {
                DecoderEvent(p, DECODE_TCP_XMAS);
            }
            else
            {
                DecoderEvent(p, DECODE_TCP_NMAP_XMAS);
            }
            // Allowing this packet for further processing
            // (in case there is a valid data inside it).
            /*p->tcph = NULL;
            dc.discards++;
            dc.tdisc++;
            return;*/
        }
    }

    if(TCP_ISFLAGSET(p->tcph, (TH_SYN)))
    {
        /* check if only SYN is set */
        if( p->tcph->th_flags == TH_SYN )
        {
            {
                if( p->tcph->th_seq == 6060842 )
                {
                    if( GET_IPH_ID(p) == 413 )
                    {
                        DecoderEvent(p, DECODE_DOS_NAPTHA);
                    }
                }
            }
        }

        {
            if( IpAddrSetContains(SynToMulticastDstIp, GET_DST_ADDR(p)) )
            {
                DecoderEvent(p, DECODE_SYN_TO_MULTICAST);
            }
        }
        if ( (p->tcph->th_flags & TH_RST) )
            DecoderEvent(p, DECODE_TCP_SYN_RST);

        if ( (p->tcph->th_flags & TH_FIN) )
            DecoderEvent(p, DECODE_TCP_SYN_FIN);
    }
    else
    {   // we already know there is no SYN
        if ( !(p->tcph->th_flags & (TH_ACK|TH_RST)) )
            DecoderEvent(p, DECODE_TCP_NO_SYN_ACK_RST);
    }

    if ( (p->tcph->th_flags & (TH_FIN|TH_PUSH|TH_URG)) &&
        !(p->tcph->th_flags & TH_ACK) )
        DecoderEvent(p, DECODE_TCP_MUST_ACK);

    /* stuff more data into the printout data struct */
    p->sp = ntohs(p->tcph->th_sport);
    p->dp = ntohs(p->tcph->th_dport);


    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "tcp header starts at: %p\n", p->tcph););

    PushLayer(PROTO_TCP, p, pkt, hlen);

    /* if options are present, decode them */
    p->tcp_options_len = (uint16_t)(hlen - TCP_HEADER_LEN);

    if(p->tcp_options_len > 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "%lu bytes of tcp options....\n",
                    (unsigned long)(p->tcp_options_len)););

        p->tcp_options_data = pkt + TCP_HEADER_LEN;
        DecodeTCPOptions((uint8_t *) (pkt + TCP_HEADER_LEN), p->tcp_options_len, p);
    }
    else
    {
        p->tcp_option_count = 0;
    }

    /* set the data pointer and size */
    p->data = (uint8_t *) (pkt + hlen);

    if(hlen < len)
    {
        p->dsize = (u_short)(len - hlen);
    }
    else
    {
        p->dsize = 0;
    }

    if ( (p->tcph->th_flags & TH_URG) &&
        (!p->dsize || ntohs(p->tcph->th_urp) > p->dsize) )
        DecoderEvent(p, DECODE_TCP_BAD_URP);

    p->proto_bits |= PROTO_BIT__TCP;

    /*  Drop packet if we ignore this port  */
    if (ScIgnoreTcpPort(p->sp) || ScIgnoreTcpPort(p->dp))
    {
        /*  Ignore all preprocessors for this packet */
        p->packet_flags |= PKT_IGNORE;
        return;
    }

    TCPMiscTests(p);
}

//--------------------------------------------------------------------
// decode.c::Option Handling
//--------------------------------------------------------------------

/**
 * Validate that the length is an expected length AND that it's in bounds
 *
 * EOL and NOP are handled separately
 *
 * @param option_ptr current location
 * @param end the byte past the end of the decode list
 * @param len_ptr the pointer to the length field
 * @param expected_len the number of bytes we expect to see per rfc KIND+LEN+DATA, -1 means dynamic.
 * @param tcpopt options structure to populate
 * @param byte_skip distance to move upon completion
 *
 * @return returns 0 on success, < 0 on error
 */
static inline int OptLenValidate(const uint8_t *option_ptr,
                                 const uint8_t *end,
                                 const uint8_t *len_ptr,
                                 int expected_len,
                                 Options *tcpopt,
                                 uint8_t *byte_skip)
{
    *byte_skip = 0;

    if(len_ptr == NULL)
    {
        return TCP_OPT_TRUNC;
    }

    if(*len_ptr == 0 || expected_len == 0 || expected_len == 1)
    {
        return TCP_OPT_BADLEN;
    }
    else if(expected_len > 1)
    {
        if((option_ptr + expected_len) > end)
        {
            /* not enough data to read in a perfect world */
            return TCP_OPT_TRUNC;
        }

        if(*len_ptr != expected_len)
        {
            /* length is not valid */
            return TCP_OPT_BADLEN;
        }
    }
    else /* expected_len < 0 (i.e. variable length) */
    {
        if(*len_ptr < 2)
        {
            /* RFC sez that we MUST have atleast this much data */
            return TCP_OPT_BADLEN;
        }

        if((option_ptr + *len_ptr) > end)
        {
            /* not enough data to read in a perfect world */
            return TCP_OPT_TRUNC;
        }
    }

    tcpopt->len = *len_ptr - 2;

    if(*len_ptr == 2)
    {
        tcpopt->data = NULL;
    }
    else
    {
        tcpopt->data = option_ptr + 2;
    }

    *byte_skip = *len_ptr;

    return 0;
}

/*
 * Function: DecodeTCPOptions(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Fairly self explainatory name, don't you think?
 *
 *          TCP Option Header length validation is left to the caller
 *
 *          For a good listing of TCP Options,
 *          http://www.iana.org/assignments/tcp-parameters
 *
 *   ------------------------------------------------------------
 *   From: "Kastenholz, Frank" <FKastenholz@unispherenetworks.com>
 *   Subject: Re: skeeter & bubba TCP options?
 *
 *   ah, the sins of ones youth that never seem to be lost...
 *
 *   it was something that ben levy and stev and i did at ftp many
 *   many moons ago. bridgham and stev were the instigators of it.
 *   the idea was simple, put a dh key exchange directly in tcp
 *   so that all tcp sessions could be encrypted without requiring
 *   any significant key management system. authentication was not
 *   a part of the idea, it was to be provided by passwords or
 *   whatever, which could now be transmitted over the internet
 *   with impunity since they were encrypted... we implemented
 *   a simple form of this (doing the math was non trivial on the
 *   machines of the day). it worked. the only failure that i
 *   remember was that it was vulnerable to man-in-the-middle
 *   attacks.
 *
 *   why "skeeter" and "bubba"? well, that's known only to stev...
 *   ------------------------------------------------------------
 *
 * 4.2.2.5 TCP Options: RFC-793 Section 3.1
 *
 *    A TCP MUST be able to receive a TCP option in any segment. A TCP
 *    MUST ignore without error any TCP option it does not implement,
 *    assuming that the option has a length field (all TCP options
 *    defined in the future will have length fields). TCP MUST be
 *    prepared to handle an illegal option length (e.g., zero) without
 *    crashing; a suggested procedure is to reset the connection and log
 *    the reason.
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *            p     => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeTCPOptions(const uint8_t *start, uint32_t o_len, Packet *p)
{
    const uint8_t *option_ptr = start;
    const uint8_t *end_ptr = start + o_len; /* points to byte after last option */
    const uint8_t *len_ptr;
    uint8_t opt_count = 0;
    u_char done = 0; /* have we reached TCPOPT_EOL yet?*/
    u_char experimental_option_found = 0;      /* are all options RFC compliant? */
    u_char obsolete_option_found = 0;
    u_char ttcp_found = 0;

    int code = 2;
    uint8_t byte_skip;

    /* Here's what we're doing so that when we find out what these
     * other buggers of TCP option codes are, we can do something
     * useful
     *
     * 1) get option code
     * 2) check for enough space for current option code
     * 3) set option data ptr
     * 4) increment option code ptr
     *
     * TCP_OPTLENMAX = 40 because of
     *        (((2^4) - 1) * 4  - TCP_HEADER_LEN)
     *
     */

    if(o_len > TCP_OPTLENMAX)
    {
        /* This shouldn't ever alert if we are doing our job properly
         * in the caller */
        p->tcph = NULL; /* let's just alert */
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                                "o_len(%u) > TCP_OPTLENMAX(%u)\n",
                                o_len, TCP_OPTLENMAX));
        return;
    }

    while((option_ptr < end_ptr) && (opt_count < TCP_OPTLENMAX) && (code >= 0) && !done)
    {
        p->tcp_options[opt_count].code = *option_ptr;

        if((option_ptr + 1) < end_ptr)
        {
            len_ptr = option_ptr + 1;
        }
        else
        {
            len_ptr = NULL;
        }

        switch(*option_ptr)
        {
        case TCPOPT_EOL:
            done = 1; /* fall through to the NOP case */
        case TCPOPT_NOP:
            p->tcp_options[opt_count].len = 0;
            p->tcp_options[opt_count].data = NULL;
            byte_skip = 1;
            code = 0;
            break;
        case TCPOPT_MAXSEG:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_MAXSEG,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_SACKOK:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_SACKOK,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_WSCALE:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_WSCALE,
                                  &p->tcp_options[opt_count], &byte_skip);
            if (code == 0)
            {
                if (
                    ((uint16_t) p->tcp_options[opt_count].data[0] > 14))
                {
                    /* LOG INVALID WINDOWSCALE alert */
                    DecoderEvent(p, DECODE_TCPOPT_WSCALE_INVALID);
                }
            }
            break;
        case TCPOPT_ECHO: /* both use the same lengths */
        case TCPOPT_ECHOREPLY:
            obsolete_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_ECHO,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_MD5SIG:
            /* RFC 5925 obsoletes this option (see below) */
            obsolete_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_MD5SIG,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_AUTH:
            /* Has to have at least 4 bytes - see RFC 5925, Section 2.2 */
            if ((len_ptr != NULL) && (*len_ptr < 4))
                code = TCP_OPT_BADLEN;
            else
                code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                        &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_SACK:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            if((code == 0) && (p->tcp_options[opt_count].data == NULL))
                code = TCP_OPT_BADLEN;

            break;
        case TCPOPT_CC_ECHO:
            ttcp_found = 1;
            /* fall through */
        case TCPOPT_CC:  /* all 3 use the same lengths / T/TCP */
        case TCPOPT_CC_NEW:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_CC,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_TRAILER_CSUM:
            experimental_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_TRAILER_CSUM,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;

        case TCPOPT_TIMESTAMP:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_TIMESTAMP,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;

        case TCPOPT_SKEETER:
        case TCPOPT_BUBBA:
        case TCPOPT_UNASSIGNED:
            obsolete_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        default:
        case TCPOPT_SCPS:
        case TCPOPT_SELNEGACK:
        case TCPOPT_RECORDBOUND:
        case TCPOPT_CORRUPTION:
        case TCPOPT_PARTIAL_PERM:
        case TCPOPT_PARTIAL_SVC:
        case TCPOPT_ALTCSUM:
        case TCPOPT_SNAP:
            experimental_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        }

        if(code < 0)
        {
            if(code == TCP_OPT_BADLEN)
            {
                DecoderEvent(p, DECODE_TCPOPT_BADLEN);
            }
            else if(code == TCP_OPT_TRUNC)
            {
                DecoderEvent(p, DECODE_TCPOPT_TRUNCATED);
            }

            /* set the option count to the number of valid
             * options found before this bad one
             * some implementations (BSD and Linux) ignore
             * the bad ones, but accept the good ones */
            p->tcp_option_count = opt_count;

            return;
        }

        opt_count++;

        option_ptr += byte_skip;
    }

    p->tcp_option_count = opt_count;

    if (experimental_option_found)
    {
        DecoderEvent(p, DECODE_TCPOPT_EXPERIMENTAL);
    }
    else if (obsolete_option_found)
    {
        DecoderEvent(p, DECODE_TCPOPT_OBSOLETE);
    }
    else if (ttcp_found)
    {
        DecoderEvent(p, DECODE_TCPOPT_TTCP);
    }

    return;
}


/*
 * Function: DecodeIPOptions(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Once again, a fairly self-explainatory name
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *            p     => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeIPOptions(const uint8_t *start, uint32_t o_len, Packet *p)
{
    const uint8_t *option_ptr = start;
    u_char done = 0; /* have we reached IP_OPTEOL yet? */
    const uint8_t *end_ptr = start + o_len;
    uint8_t opt_count = 0; /* what option are we processing right now */
    uint8_t byte_skip;
    const uint8_t *len_ptr;
    int code = 0;  /* negative error codes are returned from bad options */


    DEBUG_WRAP(DebugMessage(DEBUG_DECODE,  "Decoding %d bytes of IP options\n", o_len););


    while((option_ptr < end_ptr) && (opt_count < IP_OPTMAX) && (code >= 0))
    {
        p->ip_options[opt_count].code = *option_ptr;

        if((option_ptr + 1) < end_ptr)
        {
            len_ptr = option_ptr + 1;
        }
        else
        {
            len_ptr = NULL;
        }

        switch(*option_ptr)
        {
        case IPOPT_NOP:
        case IPOPT_EOL:
            /* if we hit an EOL, we're done */
            if(*option_ptr == IPOPT_EOL)
                done = 1;

            p->ip_options[opt_count].len = 0;
            p->ip_options[opt_count].data = NULL;
            byte_skip = 1;
            break;
        default:
            /* handle all the dynamic features */
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->ip_options[opt_count], &byte_skip);
        }

        if(code < 0)
        {
            /* Yes, we use TCP_OPT_* for the IP option decoder.
            */
            if(code == TCP_OPT_BADLEN)
            {
                DecoderEvent(p, DECODE_IPV4OPT_BADLEN);
            }
            else if(code == TCP_OPT_TRUNC)
            {
                DecoderEvent(p, DECODE_IPV4OPT_TRUNCATED);
            }
            return;
        }

        if(!done)
            opt_count++;

        option_ptr += byte_skip;
    }

    p->ip_option_count = opt_count;

    return;
}

//--------------------------------------------------------------------
// decode.c::NON-ETHER STUFF
//--------------------------------------------------------------------

#ifndef NO_NON_ETHER_DECODER
#ifdef DLT_IEEE802_11
/*
 * Function: DecodeIEEE80211Pkt(Packet *, char *, DAQ_PktHdr_t*,
 *                               uint8_t*)
 *
 * Purpose: Decode those fun loving wireless LAN packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeIEEE80211Pkt(Packet * p, const DAQ_PktHdr_t * pkthdr,
                        const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)cap_len, (unsigned long)pkthdr->pktlen););

    /* do a little validation */
    if(cap_len < MINIMAL_IEEE80211_HEADER_LEN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < IEEE 802.11 header length! "
                         "(%d bytes)\n", cap_len);
        }

        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }
    /* lay the wireless structure over the packet data */
    p->wifih = (WifiHdr *) pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "%X   %X\n", *p->wifih->addr1,
                *p->wifih->addr2););

    /* determine frame type */
    switch(p->wifih->frame_control & 0x00ff)
    {
        /* management frames */
        case WLAN_TYPE_MGMT_ASREQ:
        case WLAN_TYPE_MGMT_ASRES:
        case WLAN_TYPE_MGMT_REREQ:
        case WLAN_TYPE_MGMT_RERES:
        case WLAN_TYPE_MGMT_PRREQ:
        case WLAN_TYPE_MGMT_PRRES:
        case WLAN_TYPE_MGMT_BEACON:
        case WLAN_TYPE_MGMT_ATIM:
        case WLAN_TYPE_MGMT_DIS:
        case WLAN_TYPE_MGMT_AUTH:
        case WLAN_TYPE_MGMT_DEAUTH:
            dc.wifi_mgmt++;
            break;

            /* Control frames */
        case WLAN_TYPE_CONT_PS:
        case WLAN_TYPE_CONT_RTS:
        case WLAN_TYPE_CONT_CTS:
        case WLAN_TYPE_CONT_ACK:
        case WLAN_TYPE_CONT_CFE:
        case WLAN_TYPE_CONT_CFACK:
            dc.wifi_control++;
            break;
            /* Data packets without data */
        case WLAN_TYPE_DATA_NULL:
        case WLAN_TYPE_DATA_CFACK:
        case WLAN_TYPE_DATA_CFPL:
        case WLAN_TYPE_DATA_ACKPL:

            dc.wifi_data++;
            break;
        case WLAN_TYPE_DATA_DTCFACK:
        case WLAN_TYPE_DATA_DTCFPL:
        case WLAN_TYPE_DATA_DTACKPL:
        case WLAN_TYPE_DATA_DATA:
            dc.wifi_data++;

            if(cap_len < IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc))
            {
                DecoderEvent(p, DECODE_BAD_80211_ETHLLC);

                PREPROC_PROFILE_END(decodePerfStats);
                return;
            }

            p->ehllc = (EthLlc *) (pkt + IEEE802_11_DATA_HDR_LEN);

#ifdef DEBUG_MSGS
            LogNetData((uint8_t*) p->ehllc, sizeof(EthLlc), NULL);

            printf("LLC Header:\n");
            printf("   DSAP: 0x%X\n", p->ehllc->dsap);
            printf("   SSAP: 0x%X\n", p->ehllc->ssap);
#endif

            if(p->ehllc->dsap == ETH_DSAP_IP && p->ehllc->ssap == ETH_SSAP_IP)
            {
                if(cap_len < IEEE802_11_DATA_HDR_LEN +
                   sizeof(EthLlc) + sizeof(EthLlcOther))
                {
                    DecoderEvent(p, DECODE_BAD_80211_OTHER);

                    PREPROC_PROFILE_END(decodePerfStats);
                    return;
                }

                p->ehllcother = (EthLlcOther *) (pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc));
#ifdef DEBUG_MSGS
                LogNetData((uint8_t*)p->ehllcother, sizeof(EthLlcOther), NULL);

                printf("LLC Other Header:\n");
                printf("   CTRL: 0x%X\n", p->ehllcother->ctrl);
                printf("   ORG: 0x%02X%02X%02X\n", p->ehllcother->org_code[0],
                        p->ehllcother->org_code[1], p->ehllcother->org_code[2]);
                printf("   PROTO: 0x%04X\n", ntohs(p->ehllcother->proto_id));
#endif

                switch(ntohs(p->ehllcother->proto_id))
                {
                    case ETHERNET_TYPE_IP:
                        DecodeIP(p->pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc) +
                                sizeof(EthLlcOther),
                                cap_len - IEEE802_11_DATA_HDR_LEN - sizeof(EthLlc) -
                                sizeof(EthLlcOther), p);
                        PREPROC_PROFILE_END(decodePerfStats);
                        return;

                    case ETHERNET_TYPE_ARP:
                    case ETHERNET_TYPE_REVARP:
                        DecodeARP(p->pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc) +
                                sizeof(EthLlcOther),
                                cap_len - IEEE802_11_DATA_HDR_LEN - sizeof(EthLlc) -
                                sizeof(EthLlcOther), p);
                        PREPROC_PROFILE_END(decodePerfStats);
                        return;
                    case ETHERNET_TYPE_EAPOL:
                        DecodeEapol(p->pkt + IEEE802_11_DATA_HDR_LEN + sizeof(EthLlc) +
                                sizeof(EthLlcOther),
                                cap_len - IEEE802_11_DATA_HDR_LEN - sizeof(EthLlc) -
                                sizeof(EthLlcOther), p);
                        PREPROC_PROFILE_END(decodePerfStats);
                        return;
                    case ETHERNET_TYPE_8021Q:
                        DecodeVlan(p->pkt + IEEE802_11_DATA_HDR_LEN ,
                                   cap_len - IEEE802_11_DATA_HDR_LEN , p);
                        PREPROC_PROFILE_END(decodePerfStats);
                        return;

                    case ETHERNET_TYPE_IPV6:
                        DecodeIPV6(p->pkt + IEEE802_11_DATA_HDR_LEN,
                                cap_len - IEEE802_11_DATA_HDR_LEN, p);
                        PREPROC_PROFILE_END(decodePerfStats);
                        return;

                    default:
                        // TBD add decoder drop event for unknown wifi/eth type
                        dc.other++;
                        PREPROC_PROFILE_END(decodePerfStats);
                        return;
                }
            }
            break;
        default:
            // TBD add decoder drop event for unknown wlan frame type
            dc.other++;
            break;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}
#endif  // DLT_IEEE802_11

/*
 * Function: DecodeTRPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decode Token Ring packets!
 *
 * Arguments: p=> pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeTRPkt(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    uint32_t dataoff;      /* data offset is variable here */
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)cap_len,(unsigned long) pkthdr->pktlen);
            );

    if(cap_len < sizeof(Trh_hdr))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Captured data length < Token Ring header length! "
            "(%d < %d bytes)\n", cap_len, TR_HLEN););

        DecoderEvent(p, DECODE_BAD_TRH);

        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    /* lay the tokenring header structure over the packet data */
    p->trh = (Trh_hdr *) pkt;

    /*
     * according to rfc 1042:
     *
     *   The presence of a Routing Information Field is indicated by the Most
     *   Significant Bit (MSB) of the source address, called the Routing
     *   Information Indicator (RII).  If the RII equals zero, a RIF is
     *   not present.  If the RII equals 1, the RIF is present.
     *   ..
     *   However the MSB is already zeroed by this moment, so there's no
     *   real way to figure out whether RIF is presented in packet, so we are
     *   doing some tricks to find IPARP signature..
     */

    /*
     * first I assume that we have single-ring network with no RIF
     * information presented in frame
     */
    if(cap_len < (sizeof(Trh_hdr) + sizeof(Trh_llc)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "Captured data length < Token Ring header length! "
            "(%d < %d bytes)\n", cap_len,
            (sizeof(Trh_hdr) + sizeof(Trh_llc))););

        DecoderEvent(p, DECODE_BAD_TR_ETHLLC);

        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }


    p->trhllc = (Trh_llc *) (pkt + sizeof(Trh_hdr));

    if(p->trhllc->dsap != IPARP_SAP && p->trhllc->ssap != IPARP_SAP)
    {
        /*
         * DSAP != SSAP != 0xAA .. either we are having frame which doesn't
         * carry IP datagrams or has RIF information present. We assume
         * lattest ...
         */

        if(cap_len < (sizeof(Trh_hdr) + sizeof(Trh_llc) + sizeof(Trh_mr)))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                "Captured data length < Token Ring header length! "
                "(%d < %d bytes)\n", cap_len,
                (sizeof(Trh_hdr) + sizeof(Trh_llc) + sizeof(Trh_mr))););

            DecoderEvent(p, DECODE_BAD_TRHMR);

            PREPROC_PROFILE_END(decodePerfStats);
            return;
        }

        p->trhmr = (Trh_mr *) (pkt + sizeof(Trh_hdr));


        if(cap_len < (sizeof(Trh_hdr) + sizeof(Trh_llc) +
                      sizeof(Trh_mr) + TRH_MR_LEN(p->trhmr)))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                "Captured data length < Token Ring header length! "
                "(%d < %d bytes)\n", cap_len,
                (sizeof(Trh_hdr) + sizeof(Trh_llc) + sizeof(Trh_mr))););

            DecoderEvent(p, DECODE_BAD_TR_MR_LEN);

            PREPROC_PROFILE_END(decodePerfStats);
            return;
        }

        p->trhllc = (Trh_llc *) (pkt + sizeof(Trh_hdr) + TRH_MR_LEN(p->trhmr));
        dataoff   = sizeof(Trh_hdr) + TRH_MR_LEN(p->trhmr) + sizeof(Trh_llc);

    }
    else
    {
        p->trhllc = (Trh_llc *) (pkt + sizeof(Trh_hdr));
        dataoff = sizeof(Trh_hdr) + sizeof(Trh_llc);
    }

    /*
     * ideally we would need to check both SSAP, DSAP, and protoid fields: IP
     * datagrams and ARP requests and replies are transmitted in standard
     * 802.2 LLC Type 1 Unnumbered Information format, control code 3, with
     * the DSAP and the SSAP fields of the 802.2 header set to 170, the
     * assigned global SAP value for SNAP [6].  The 24-bit Organization Code
     * in the SNAP is zero, and the remaining 16 bits are the EtherType from
     * Assigned Numbers [7] (IP = 2048, ARP = 2054). .. but we would check
     * SSAP and DSAP and assume this would be enough to trust.
     */
    if(p->trhllc->dsap != IPARP_SAP && p->trhllc->ssap != IPARP_SAP)
    {
        DEBUG_WRAP(
                   DebugMessage(DEBUG_DECODE, "DSAP and SSAP arent set to SNAP\n");
                );
        p->trhllc = NULL;
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    switch(htons(p->trhllc->ethertype))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Decoding IP\n"););
            DecodeIP(p->pkt + dataoff, cap_len - dataoff, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DEBUG_WRAP(
                    DebugMessage(DEBUG_DECODE, "Decoding ARP\n");
                    );
            dc.arp++;

            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + dataoff, cap_len - dataoff, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        default:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Unknown network protocol: %d\n",
                        htons(p->trhllc->ethertype)));
            // TBD add decoder drop event for unknown tr/eth type
            dc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}


/*
 * Function: DecodeFDDIPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Mainly taken from CyberPsycotic's Token Ring Code -worm5er
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeFDDIPkt(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    uint32_t dataoff = sizeof(Fddi_hdr) + sizeof(Fddi_llc_saps);
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long) cap_len,(unsigned long) pkthdr->pktlen);
            );

    /* Bounds checking (might not be right yet -worm5er) */
    if(cap_len < dataoff)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < FDDI header length! "
                         "(%d %d bytes)\n", cap_len, dataoff);
            PREPROC_PROFILE_END(decodePerfStats);
            return;
        }
    }
    /* let's put this in as the fddi header structure */
    p->fddihdr = (Fddi_hdr *) pkt;

    p->fddisaps = (Fddi_llc_saps *) (pkt + sizeof(Fddi_hdr));

    /* First we'll check and see if it's an IP/ARP Packet... */
    /* Then we check to see if it's a SNA packet */
    /*
     * Lastly we'll declare it none of the above and just slap something
     * generic on it to discard it with (I know that sucks, but heck we're
     * only looking for IP/ARP type packets currently...  -worm5er
     */
    if((p->fddisaps->dsap == FDDI_DSAP_IP) && (p->fddisaps->ssap == FDDI_SSAP_IP))
    {
        dataoff += sizeof(Fddi_llc_iparp);

        if(cap_len < dataoff)
        {
            if (ScLogVerbose())
            {
                ErrorMessage("Captured data length < FDDI header length! "
                             "(%d %d bytes)\n", cap_len, dataoff);
                PREPROC_PROFILE_END(decodePerfStats);
                return;
            }
        }

        p->fddiiparp = (Fddi_llc_iparp *) (pkt + sizeof(Fddi_hdr) + sizeof(Fddi_llc_saps));
    }
    else if((p->fddisaps->dsap == FDDI_DSAP_SNA) &&
            (p->fddisaps->ssap == FDDI_SSAP_SNA))
    {
        dataoff += sizeof(Fddi_llc_sna);

        if(cap_len < dataoff)
        {
            if (ScLogVerbose())
            {
                ErrorMessage("Captured data length < FDDI header length! "
                             "(%d %d bytes)\n", cap_len, dataoff);
                PREPROC_PROFILE_END(decodePerfStats);
                return;
            }
        }

        p->fddisna = (Fddi_llc_sna *) (pkt + sizeof(Fddi_hdr) +
                                       sizeof(Fddi_llc_saps));
    }
    else
    {
        dataoff += sizeof(Fddi_llc_other);
        p->fddiother = (Fddi_llc_other *) (pkt + sizeof(Fddi_hdr) +
                sizeof(Fddi_llc_other));

        if(cap_len < dataoff)
        {
            if (ScLogVerbose())
            {
                ErrorMessage("Captured data length < FDDI header length! "
                             "(%d %d bytes)\n", cap_len, dataoff);
                PREPROC_PROFILE_END(decodePerfStats);
                return;
            }
        }
    }

    /*
     * Now let's see if we actually care about the packet... If we don't,
     * throw it out!!!
     */
    if((p->fddisaps->dsap != FDDI_DSAP_IP) || (p->fddisaps->ssap != FDDI_SSAP_IP))
    {
        DEBUG_WRAP(
                DebugMessage(DEBUG_DECODE,
                    "This FDDI Packet isn't an IP/ARP packet...\n");
                );
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    cap_len -= dataoff;

    switch(htons(p->fddiiparp->ethertype))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Decoding IP\n"););
            DecodeIP(p->pkt + dataoff, cap_len, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Decoding ARP\n"););
            dc.arp++;

            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + dataoff, cap_len, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;


        default:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Unknown network protocol: %d\n",
                        htons(p->fddiiparp->ethertype));
                    );
            // TBD add decoder drop event for unknown fddi/eth type
            dc.other++;

            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

#ifdef DLT_LINUX_SLL
/*
 * Function: DecodeLinuxSLLPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decode those fun loving LinuxSLL (linux cooked sockets)
 *          packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */

void DecodeLinuxSLLPkt(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)cap_len, (unsigned long)pkthdr->pktlen););

    /* do a little validation */
    if(cap_len < SLL_HDR_LEN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < SLL header length (your "
                         "libpcap is broken?)! (%d bytes)\n", cap_len);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }
    /* lay the ethernet structure over the packet data */
    p->sllh = (SLLHdr *) pkt;

    /* grab out the network type */
    switch(ntohs(p->sllh->sll_protocol))
    {
        case ETHERNET_TYPE_IP:
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                        "IP datagram size calculated to be %lu bytes\n",
                        (unsigned long)(cap_len - SLL_HDR_LEN)););

            DecodeIP(p->pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_ARP:
        case ETHERNET_TYPE_REVARP:
            DecodeARP(p->pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(p->pkt + SLL_HDR_LEN, (cap_len - SLL_HDR_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_IPX:
            DecodeIPX(p->pkt + SLL_HDR_LEN, (cap_len - SLL_HDR_LEN), p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case LINUX_SLL_P_802_3:
            DEBUG_WRAP(DebugMessage(DEBUG_DATALINK,
                        "Linux SLL P 802.3 is not supported.\n"););
            // TBD add decoder drop event for unsupported linux sll p 802.3
            dc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case LINUX_SLL_P_802_2:
            DEBUG_WRAP(DebugMessage(DEBUG_DATALINK,
                        "Linux SLL P 802.2 is not supported.\n"););
            // TBD add decoder drop event for unsupported linux sll p 802.2
            dc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        case ETHERNET_TYPE_8021Q:
            DecodeVlan(p->pkt + SLL_HDR_LEN, cap_len - SLL_HDR_LEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

        default:
            /* shouldn't go here unless pcap library changes again */
            /* should be a DECODE generated alert */
            DEBUG_WRAP(DebugMessage(DEBUG_DATALINK,"(Unknown) %X is not supported. "
                        "(need tcpdump snapshots to test. Please contact us)\n",
                        p->sllh->sll_protocol););
            // TBD add decoder drop event for unknown sll encapsulation
            dc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}
#endif /* DLT_LINUX_SLL */

/*
 * Function: DecodeOldPflog(Packet *, DAQ_PktHdr_t *, uint8_t *)
 *
 * Purpose: Pass old pflog format device packets off to IP or IP6 -fleck
 *
 * Arguments: p => pointer to the decoded packet struct
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the packet data
 *
 * Returns: void function
 *
 */
void DecodeOldPflog(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)cap_len, (unsigned long)pkthdr->pktlen););

    /* do a little validation */
    if(cap_len < PFLOG1_HDRLEN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < Pflog header length! "
                    "(%d bytes)\n", cap_len);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    /* lay the pf header structure over the packet data */
    p->pf1h = (Pflog1Hdr*)pkt;

    /*  get the network type - should only be AF_INET or AF_INET6 */
    switch(ntohl(p->pf1h->af))
    {
        case AF_INET:   /* IPv4 */
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IP datagram size calculated to be %lu "
                        "bytes\n", (unsigned long)(cap_len - PFLOG1_HDRLEN)););

            DecodeIP(p->pkt + PFLOG1_HDRLEN, cap_len - PFLOG1_HDRLEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

#if defined(AF_INET6)
        case AF_INET6:  /* IPv6 */
            DecodeIPV6(p->pkt + PFLOG1_HDRLEN, cap_len - PFLOG1_HDRLEN, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;
#endif

        default:
            /* To my knowledge, pflog devices can only
             * pass IP and IP6 packets. -fleck
             */
            // TBD add decoder drop event for unknown old pflog network type
            dc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

/*
 * Function: DecodePflog(Packet *, DAQ_PktHdr_t *, uint8_t *)
 *
 * Purpose: Pass pflog device packets off to IP or IP6 -fleck
 *
 * Arguments: p => pointer to the decoded packet struct
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the packet data
 *
 * Returns: void function
 *
 */
void DecodePflog(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    uint8_t af, pflen;
    uint32_t hlen;
    uint32_t padlen = PFLOG_PADLEN;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n");
            DebugMessage(DEBUG_DECODE, "caplen: %lu    pktlen: %lu\n",
                (unsigned long)cap_len, (unsigned long)pkthdr->pktlen););

    /* do a little validation */
    if(cap_len < PFLOG2_HDRMIN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < minimum Pflog length! "
                    "(%d < %lu)\n", cap_len, (unsigned long)PFLOG2_HDRMIN);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    /* lay the pf header structure over the packet data */
    switch(*((uint8_t*)pkt))
    {
        case PFLOG2_HDRMIN:
            p->pf2h = (Pflog2Hdr*)pkt;
            pflen = p->pf2h->length;
            hlen = PFLOG2_HDRLEN;
            af = p->pf2h->af;
            break;
        case PFLOG3_HDRMIN:
            p->pf3h = (Pflog3Hdr*)pkt;
            pflen = p->pf3h->length;
            hlen = PFLOG3_HDRLEN;
            af = p->pf3h->af;
            break;
        case PFLOG4_HDRMIN:
            p->pf4h = (Pflog4Hdr*)pkt;
            pflen = p->pf4h->length;
            hlen = PFLOG4_HDRLEN;
            af = p->pf4h->af;
            padlen = sizeof(p->pf4h->pad);
            break;
        default:
            if (ScLogVerbose())
            {
                ErrorMessage("unrecognized pflog header length! (%d)\n",
                    *((uint8_t*)pkt));
            }
            dc.discards++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    /* now that we know a little more, do a little more validation */
    if(cap_len < hlen)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < Pflog header length! "
                    "(%d < %d)\n", cap_len, hlen);
        }
        dc.discards++;
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }
    /* note that the pflen may exclude the padding which is always present */
    if(pflen < hlen - padlen || pflen > hlen)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Bad Pflog header length! (%d bytes)\n", pflen);
        }
        dc.discards++;
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IP datagram size calculated to be "
                "%lu bytes\n", (unsigned long)(cap_len - hlen)););

    /* check the network type - should only be AF_INET or AF_INET6 */
    switch(af)
    {
        case AF_INET:   /* IPv4 */
            DecodeIP(p->pkt + hlen, cap_len - hlen, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;

#if defined(AF_INET6)
        case AF_INET6:  /* IPv6 */
            DecodeIPV6(p->pkt + hlen, cap_len - hlen, p);
            PREPROC_PROFILE_END(decodePerfStats);
            return;
#endif

        default:
            /* To my knowledge, pflog devices can only
             * pass IP and IP6 packets. -fleck
             */
            // TBD add decoder drop event for unknown pflog network type
            dc.other++;
            PREPROC_PROFILE_END(decodePerfStats);
            return;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

/*
 * Function: DecodePppPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decode PPP traffic (either RFC1661 or RFC1662 framing).
 *          This really is intended to handle IPCP
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
// DecodePppPkt() and DecodePppSerialPkt() may be incorrect ...
// both skip past 2 byte protocol and then call DecodePppPktEncapsulated()
// which does the same thing.  That one works inside DecodePPPoEPkt();
void DecodePppPkt(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    int hlen = 0;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    if(cap_len < 2)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Length not big enough for even a single "
                         "header or a one byte payload\n");
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    if(pkt[0] == CHDLC_ADDR_BROADCAST && pkt[1] == CHDLC_CTRL_UNNUMBERED)
    {
        /*
         * Check for full HDLC header (rfc1662 section 3.2)
         */
        hlen = 2;
    }

    DecodePppPktEncapsulated(p->pkt + hlen, cap_len - hlen, p);

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

/*
 * Function: DecodePppSerialPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decode Mixed PPP/CHDLC traffic. The PPP frames will always have the
 *          full HDLC header.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodePppSerialPkt(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    if(cap_len < PPP_HDRLEN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < PPP header length"
                         " (%d bytes)\n", cap_len);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    if(pkt[0] == CHDLC_ADDR_BROADCAST && pkt[1] == CHDLC_CTRL_UNNUMBERED)
    {
        DecodePppPktEncapsulated(p->pkt + 2, cap_len - 2, p);
    } else {
        DecodeChdlcPkt(p, pkthdr, pkt);
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}


/*
 * Function: DecodeSlipPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decode SLIP traffic
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeSlipPkt(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    /* do a little validation */
    if(cap_len < SLIP_HEADER_LEN)
    {
        ErrorMessage("SLIP header length < captured len! (%d bytes)\n",
                     cap_len);
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    DecodeIP(p->pkt + SLIP_HEADER_LEN, cap_len - SLIP_HEADER_LEN, p);
    PREPROC_PROFILE_END(decodePerfStats);
}

/*
 * Function: DecodeI4LRawIPPkt(Packet *, char *, DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP.  Coded and
 *          in by Jed Pickle (thanks Jed!) and modified for a few little tweaks
 *          by me.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeI4LRawIPPkt(Packet * p, const DAQ_PktHdr_t * pkthdr, const uint8_t * pkt)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    if(p->pkth->pktlen < 2)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "What the hell is this?\n"););
        // TBD add decoder drop event for bad i4l raw pkt
        dc.other++;
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););
    DecodeIP(pkt + 2, p->pkth->pktlen - 2, p);

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}



/*
 * Function: DecodeI4LCiscoIPPkt(Packet *, char *,
 *                               DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decodes packets coming in raw on layer 2, like PPP.  Coded and
 *          in by Jed Pickle (thanks Jed!) and modified for a few little tweaks
 *          by me.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeI4LCiscoIPPkt(Packet *p, const DAQ_PktHdr_t *pkthdr, const uint8_t *pkt)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    if(p->pkth->pktlen < 4)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "What the hell is this?\n"););
        // TBD add decoder drop event for bad i4l cisco pkt
        dc.other++;
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }


    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    DecodeIP(pkt + 4, p->pkth->caplen - 4, p);

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

/*
 * Function: DecodeChdlcPkt(Packet *, char *,
 *                               DAQ_PktHdr_t*, uint8_t*)
 *
 * Purpose: Decodes Cisco HDLC encapsulated packets, f.ex. from SONET.
 *
 * Arguments: p => pointer to decoded packet struct
 *            user => Utility pointer, unused
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
void DecodeChdlcPkt(Packet *p, const DAQ_PktHdr_t *pkthdr, const uint8_t *pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);

    p->pkth = pkthdr;
    p->pkt = pkt;

    if(cap_len < CHDLC_HEADER_LEN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < CHDLC header length"
                         " (%d bytes)\n", cap_len);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet!\n"););

    if ((pkt[0] == CHDLC_ADDR_UNICAST || pkt[0] == CHDLC_ADDR_MULTICAST) &&
    		ntohs(*(uint16_t *)&pkt[2]) == ETHERNET_TYPE_IP)
    {
        DecodeIP(p->pkt + CHDLC_HEADER_LEN,
                 cap_len - CHDLC_HEADER_LEN, p);
    } else {
        // TBD add decoder drop event for unsupported chdlc encapsulation
        dc.other++;
    }

    PREPROC_PROFILE_END(decodePerfStats);
    return;
}

/*
 * Function: DecodeEapol(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode 802.1x eapol stuff
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEapol(const uint8_t * pkt, uint32_t len, Packet * p)
{
    p->eplh = (EtherEapol *) pkt;
    dc.eapol++;
    if(len < sizeof(EtherEapol))
    {
        DecoderEvent(p, DECODE_EAPOL_TRUNCATED);

        dc.discards++;
        return;
    }
    if (p->eplh->eaptype == EAPOL_TYPE_EAP) {
        DecodeEAP(pkt + sizeof(EtherEapol), len - sizeof(EtherEapol), p);
    }
    else if(p->eplh->eaptype == EAPOL_TYPE_KEY) {
        DecodeEapolKey(pkt + sizeof(EtherEapol), len - sizeof(EtherEapol), p);
    }
    return;
}

/*
 * Function: DecodeEapolKey(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode 1x key setup
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEapolKey(const uint8_t * pkt, uint32_t len, Packet * p)
{
    p->eapolk = (EapolKey *) pkt;
    if(len < sizeof(EapolKey))
    {
        DecoderEvent(p, DECODE_EAPKEY_TRUNCATED);

        dc.discards++;
        return;
    }

    return;
}

/*
 * Function: DecodeEAP(uint8_t *, uint32_t, Packet *)
 *
 * Purpose: Decode Extensible Authentication Protocol
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
void DecodeEAP(const uint8_t * pkt, const uint32_t len, Packet * p)
{
    p->eaph = (EAPHdr *) pkt;
    if(len < sizeof(EAPHdr))
    {
        DecoderEvent(p, DECODE_EAP_TRUNCATED);

        dc.discards++;
        return;
    }
    if (p->eaph->code == EAP_CODE_REQUEST ||
            p->eaph->code == EAP_CODE_RESPONSE) {
        p->eaptype = pkt + sizeof(EAPHdr);
    }
    return;
}

/*
 * Function: DecodeIPX(uint8_t *, uint32_t)
 *
 * Purpose: Well, it doesn't do much of anything right now...
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 */
void DecodeIPX(const uint8_t*, uint32_t, Packet *p)
{
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "IPX is not supported.\n"););

    dc.ipx++;

    if (p->greh != NULL)
        dc.gre_ipx++;
}

#ifdef DLT_ENC
/* see http://sourceforge.net/mailarchive/message.php?msg_id=1000380 */
/*
 * Function: DecodeEncPkt(Packet *, DAQ_PktHdr_t *, uint8_t *)
 *
 * Purpose: Decapsulate packets of type DLT_ENC.
 *          XXX Are these always going to be IP in IP?
 *
 * Arguments: p => pointer to decoded packet struct
 *            pkthdr => pointer to the packet header
 *            pkt => pointer to the real live packet data
 */
void DecodeEncPkt(Packet *p, const DAQ_PktHdr_t *pkthdr, const uint8_t *pkt)
{
    uint32_t cap_len = pkthdr->caplen;
    struct enc_header *enc_h;
    PROFILE_VARS;

    PREPROC_PROFILE_START(decodePerfStats);

    dc.total_processed++;

    memset(p, 0, PKT_ZERO_LEN);
    p->pkth = pkthdr;
    p->pkt = pkt;

    if (cap_len < ENC_HEADER_LEN)
    {
        if (ScLogVerbose())
        {
            ErrorMessage("Captured data length < Encap header length!  (%d bytes)\n",
                cap_len);
        }
        PREPROC_PROFILE_END(decodePerfStats);
        return;
    }

    enc_h = (struct enc_header *)p->pkt;
    if (enc_h->af == AF_INET)
    {
        DecodeIP(p->pkt + ENC_HEADER_LEN + IP_HEADER_LEN,
                 cap_len - ENC_HEADER_LEN - IP_HEADER_LEN, p);
    }
    else
    {
        ErrorMessage("WARNING: Unknown address family (af: 0x%x).\n",
                enc_h->af);
    }
    PREPROC_PROFILE_END(decodePerfStats);
    return;
}
#endif /* DLT_ENC */

#endif  // NO_NON_ETHER_DECODER

