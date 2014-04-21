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


#include "framework/codec.h"
#include "codecs/codec_events.h"
#include "codecs/decode_module.h"
#include "protocols/ethertypes.h"
#include "snort.h"
#include "protocols/ipv4.h"

namespace
{

class PppEncap : public Codec
{
public:
    PppEncap() : Codec("PPPEncapsulation"){};
    ~PppEncap(){};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &p_hdr_len, int &next_prot_id);
    virtual void get_protocol_ids(std::vector<uint16_t>&);


    // DELETE from here and below
    #include "codecs/sf_protocols.h"
    virtual inline PROTO_ID get_proto_id() { return PROTO_PPP_ENCAP; };
    
};

const static uint16_t PPP_IP = 0x0021;       /* Internet Protocol */
const static uint16_t PPP_IPV6 = 0x0057;        /* Internet Protocol v6 */
const static uint16_t PPP_VJ_COMP = 0x002d;        /* VJ compressed TCP/IP */
const static uint16_t PPP_VJ_UCOMP = 0x002f;        /* VJ uncompressed TCP/IP */
const static uint16_t PPP_IPX = 0x002b;        /* Novell IPX Protocol */

} // anonymous namespace





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
bool PppEncap::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &p_hdr_len, int &next_prot_id)
{
    static THREAD_LOCAL bool had_vj = false;
    uint16_t protocol;

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "PPP Packet!\n"););

#ifdef WORDS_MUSTALIGN
    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Packet with PPP header.  "
                            "PPP is only 1 or 2 bytes and will throw off "
                            "alignment on this architecture when decoding IP, "
                            "causing a bus error - stop decoding packet.\n"););

    p->data = raw_pkt;
    p->dsize = (uint16_t)len;
    next_prot_id = -1;
    return true;
#endif  /* WORDS_MUSTALIGN */

//    if (p->greh != NULL)
//        dc.gre_ppp++;

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
        return false;
    }


    if(raw_pkt[0] & 0x01)
    {
        /* Check for protocol compression rfc1661 section 5
         *
         */
        p_hdr_len = 1;
        protocol = raw_pkt[0];
    }
    else
    {
        protocol = ntohs(*((uint16_t *)raw_pkt));
        p_hdr_len = 2;
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
            had_vj = true;
            return false;
        case PPP_VJ_UCOMP:
            /* VJ compression modifies the protocol field. It must be set
             * to tcp (only TCP packets can be VJ compressed) */
            if(len < (p_hdr_len + ipv4::hdr_len()))
            {
                if (ScLogVerbose())
                    ErrorMessage("PPP VJ min packet length > captured len! "
                                 "(%d bytes)\n", len);
                return false;
            }

            ((IPHdr *)(raw_pkt + p_hdr_len))->ip_proto = IPPROTO_TCP;
            /* fall through */

        case PPP_IP:
            next_prot_id = ETHERTYPE_IPV4;
            break;

        case PPP_IPV6:
            next_prot_id = ETHERTYPE_IPV6;
            break;

        case PPP_IPX:
            next_prot_id = ETHERTYPE_IPX;
            break;

        default:
            next_prot_id = -1;
            break;
    }
    return true;
}




void PppEncap::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_PPP);
}

static Codec* ctor()
{
    return new PppEncap();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static void sum()
{
//    sum_stats((PegCount*)&gdc, (PegCount*)&dc, array_size(dc_pegs));
//    memset(&dc, 0, sizeof(dc));
}

static void stats()
{
//    show_percent_stats((PegCount*)&gdc, dc_pegs, array_size(dc_pegs),
//        "decoder");
}



static const char* name = "pppencap_codec";

static const CodecApi pppencap_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
    sum, // sum
    stats  // stats
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &pppencap_api.base,
    nullptr
};
#else
const BaseApi* cd_pppencap = &pppencap_api.base;
#endif




