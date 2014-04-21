/* $Id: decode.c,v 1.285 2013-06-29 03:03:00 rcombs Exp $ */

/*
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



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "generators.h"
#include "decode.h"  
#include "static_include.h"


#include "../decoder_includes.h"


#ifdef DLT_LINUX_SLL  // WHERE IS THIS DEFINED!!


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

