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

#include "prot_transbridge.h"
#include "prot_arp.h"
#include "prot_vlan.h"
#include "prot_ipv6.h"
#include "prot_ipv4.h"
#include "prot_ethloopback.h"
#include "prot_ipx.h"

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
bool TransBridging::Decode(const uint8_t *pkt, const uint32_t len, 
        Packet *p, uint16_t &p_hdr_len, uint16_t &next_prot_id)
{
    dc.gre_eth++;

    if(len < ETHERNET_HEADER_LEN)
    {
        DecoderAlertEncapsulated(p, DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR,
                        DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR_STR,
                        pkt, len);
        return;
    }

    /* The Packet struct's ethernet header will now point to the inner ethernet
     * header of the packet
     */
    p->eh = (eth::EtherHdr *)pkt;
//    PushLayer(PROTO_ETH, p, pkt, sizeof(*p->eh));

    p_hdr_len = ETHERNET_HEADER_LEN;
    next_prot_id = ntohs(p->eh->ether_type);

    return true;
}


static const char* name = "transbridge_decode";

static const CodecApi transbridge_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    {GRE_TYPE_TRANS_BRIDGING},  
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    NULL, // ctor
    NULL, // dtor
    GRE::Decode,
};



