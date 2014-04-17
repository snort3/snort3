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
#include "prot_erspan2.h"


#include "decoder_includes.h"

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
bool ERSPANType2::Decode(const uint8_t *pkt, const uint32_t len, 
        Packet *p, uint16_t &p_hdr_len, uint16_t &next_prot_id)
{
    uint32_t hlen = sizeof(ERSpanType2Hdr);
    uint32_t payload_len;
    ERSpanType2Hdr *erSpan2Hdr = (ERSpanType2Hdr *)pkt;

    if (len < sizeof(ERSpanType2Hdr))
    {
        CodecEvents::decoder_alert_encapsulated(p, DECODE_ERSPAN2_DGRAM_LT_HDR, pkt, len);
        return;
    }

    if (p->encapsulated)
    {
        /* discard packet - multiple encapsulation */
        /* not sure if this is ever used but I am assuming it is not */
        CodecEvents::decoder_alert_encapsulated(p, DECODE_IP_MULTIPLE_ENCAPSULATION,
                        pkt, len);
        return;
    }

    /* Check that this is in fact ERSpan Type 2.
     */
    if (ERSPAN_VERSION(erSpan2Hdr) != 0x01) /* Type 2 == version 0x01 */
    {
        CodecEvents::decoder_alert_encapsulated(p, DECODE_ERSPAN_HDR_VERSION_MISMATCH,
                        pkt, len);
        return;
    }

//    PushLayer(PROTO_ERSPAN, p, pkt, hlen);
    payload_len = len - hlen;

    // TODO: Is this actually statis or possible changable?
//    DecodeTransBridging(pkt + hlen, payload_len, p);

    next_prot_id = GRE_TYPE_TRANS_BRIDGING; // huh?
    p_hdr_len = hlen;
    return true;
}

static const char* name = "erspan2_decode";

static const CodecApi erspan2_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    {ETHERNET_TYPE_ERSPAN_TYPE2},  
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
    NULL,
    NULL,
};

