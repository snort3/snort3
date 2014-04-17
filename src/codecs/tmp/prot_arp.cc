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
#include "prot_arp.h"

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
bool ARP::Decode(const uint8_t *pkt, const uint32_t len, 
        Packet *p, uint16_t &p_hdr_len, int32_t &next_prot_id)
{
    dc.arp++;

    if (p->greh != NULL)
        dc.gre_arp++;

    p->ah = (EtherARP *) pkt;

    if(len < sizeof(EtherARP))
    {
        DecoderEvent(p, DECODE_ARP_TRUNCATED,
                        DECODE_ARP_TRUNCATED_STR);

        dc.discards++;
        return false;
    }

    p->proto_bits |= PROTO_BIT__ARP;
//    PushLayer(PROTO_ARP, p, pkt, sizeof(*p->ah));
    p_hdr_len = sizeof(*p->ah);
    next_prot_id = -1;

    return true;
}


static const char* name = "arp_decode";

static const CodecApi arp_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    {ETHERNET_TYPE_ARP, ETHERNET_TYPE_REVARP},  
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    NULL, // ctor
    NULL, // dtor
    ARP::Decode,
    NULL,
    NULL
};


