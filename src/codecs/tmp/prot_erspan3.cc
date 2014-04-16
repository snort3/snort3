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


#include "decoder_includes.h"
#include "prot_erspan3.h"


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
        DecoderAlertEncapsulated(p, DECODE_ERSPAN3_DGRAM_LT_HDR,
                        DECODE_ERSPAN3_DGRAM_LT_HDR_STR,
                        pkt, len);
        return;
    }

    if (p->encapsulated)
    {
        /* discard packet - multiple encapsulation */
        /* not sure if this is ever used but I am assuming it is not */
        DecoderAlertEncapsulated(p, DECODE_IP_MULTIPLE_ENCAPSULATION,
                        DECODE_IP_MULTIPLE_ENCAPSULATION_STR,
                        pkt, len);
        return;
    }

    /* Check that this is in fact ERSpan Type 3.
     */
    if (ERSPAN_VERSION(erSpan3Hdr) != 0x02) /* Type 3 == version 0x02 */
    {
        DecoderAlertEncapsulated(p, DECODE_ERSPAN_HDR_VERSION_MISMATCH,
                        DECODE_ERSPAN_HDR_VERSION_MISMATCH_STR,
                        pkt, len);
        return;
    }

//    PushLayer(PROTO_ERSPAN, p, pkt, hlen);
//    payload_len = len - hlen;

//      TODO:  Is this the only next protocol which can be called?
//    DecodeTransBridging(pkt + hlen, payload_len, p);


    next_prot_id = GRE_TYPE_TRANS_BRIDGING; // huh?
    p_hdr_len = hlen;
    return true;
}


static const char* name = "erspan3_decode";

static const CodecApi erspan3_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    {ETHERNET_TYPE_ERSPAN_TYPE3},  
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    NULL, // ctor
    NULL, // dtor
    ErspanType2::DecodeTCP,
};

