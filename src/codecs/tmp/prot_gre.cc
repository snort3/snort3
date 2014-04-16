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
#include "prot_gre.h"

// other decoders
#include "decoder_includes.h"
#include "prot_arp.h"
#include "prot_ethloopback.h"
#include "prot_pppencap.h"



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
bool GRE::Decode(const uint8_t *pkt, const uint32_t len, 
        Packet *p, uint16_t &p_hdr_len, uint16_t &next_prot_id)
{
    uint32_t hlen;    /* GRE header length */
    uint32_t payload_len;

    if (len < GRE_HEADER_LEN)
    {
        DecoderAlertEncapsulated(p, DECODE_GRE_DGRAM_LT_GREHDR,
                        DECODE_GRE_DGRAM_LT_GREHDR_STR,
                        pkt, len);
        return;
    }

    if (p->encapsulated)
    {
        /* discard packet - multiple GRE encapsulation */
        /* not sure if this is ever used but I am assuming it is not */
        DecoderAlertEncapsulated(p, DECODE_IP_MULTIPLE_ENCAPSULATION,
                        DECODE_IP_MULTIPLE_ENCAPSULATION_STR,
                        pkt, len);
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
                DecoderAlertEncapsulated(p, DECODE_GRE_INVALID_HEADER,
                                DECODE_GRE_INVALID_HEADER_STR,
                                pkt, len);
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
                DecoderAlertEncapsulated(p, DECODE_GRE_V1_INVALID_HEADER,
                                DECODE_GRE_V1_INVALID_HEADER_STR,
                                pkt, len);
                return;
            }

            /* protocol must be 0x880B - PPP */
            if (GRE_PROTO(p->greh) != GRE_TYPE_PPP)
            {
                DecoderAlertEncapsulated(p, DECODE_GRE_V1_INVALID_HEADER,
                                DECODE_GRE_V1_INVALID_HEADER_STR,
                                pkt, len);
                return;
            }

            /* this flag should always be present */
            if (!(GRE_KEY(p->greh)))
            {
                DecoderAlertEncapsulated(p, DECODE_GRE_V1_INVALID_HEADER,
                                DECODE_GRE_V1_INVALID_HEADER_STR,
                                pkt, len);
                return;
            }

            hlen += GRE_KEY_LEN;

            if (GRE_SEQ(p->greh))
                hlen += GRE_SEQ_LEN;

            if (GRE_V1_ACK(p->greh))
                hlen += GRE_V1_ACK_LEN;

            break;

        default:
            DecoderAlertEncapsulated(p, DECODE_GRE_INVALID_VERSION,
                            DECODE_GRE_INVALID_VERSION_STR,
                            pkt, len);
            return;
    }

    if (hlen > len)
    {
        DecoderAlertEncapsulated(p, DECODE_GRE_DGRAM_LT_GREHDR,
                        DECODE_GRE_DGRAM_LT_GREHDR_STR,
                        pkt, len);
        return;
    }

    PushLayer(PROTO_GRE, p, pkt, hlen);
    payload_len = len - hlen;

    p_hdr_len = hlen;
    next_prot_id = GRE_PROTO(p->greh);
    return true;
}

/*
 * ENCODER
 */
void GRE_Format (EncodeFlags, const Packet*, Packet* c, Layer* lyr)
{
    c->greh = (GREHdr*)lyr->start;
}





void GreCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_GRE);
}

static Codec* ctor()
{
    return new GreCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}




static const char* name = "gre_decode";

static const CodecApi udp_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
};

