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
#include "prot_ethovermpls.h"


#include "decoder_includes.h"
#include "prot_arp.h"
#include "prot_ethloopback.h"
#include "prot_pppoepkt.h"

//--------------------------------------------------------------------
// decode.c::MPLS
//--------------------------------------------------------------------

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
    p->eh = (eth::EtherHdr *) pkt; // FIXTHIS squashes outer eth!
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

