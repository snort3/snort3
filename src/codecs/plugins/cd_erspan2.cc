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


#include "framework/codec.h"
#include "codecs/codec_events.h"
#include "codecs/decode_module.h"
#include "protocols/ethertypes.h"

namespace
{

class Erspan2Codec : public Codec
{
public:
    Erspan2Codec() : Codec("ERSPAN_2"){};
    ~Erspan2Codec(){};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &p_hdr_len, int &next_prot_id);
    
    // DELETE from here and below
    #include "codecs/sf_protocols.h"
    virtual inline PROTO_ID get_proto_id() { return PROTO_ERSPAN; };
};


struct ERSpanType2Hdr
{
    uint16_t ver_vlan;
    uint16_t flags_spanId;
    uint32_t pad;
} ;

const uint16_t ETHERTYPE_ERSPAN_TYPE2 = 0x88be;
} // anonymous namespace




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
bool Erspan2Codec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &p_hdr_len, int &next_prot_id)
{
    p_hdr_len = sizeof(ERSpanType2Hdr);
    uint32_t payload_len;
    ERSpanType2Hdr *erSpan2Hdr = (ERSpanType2Hdr *)raw_pkt;

    if (len < sizeof(ERSpanType2Hdr))
    {
        CodecEvents::decoder_alert_encapsulated(p, DECODE_ERSPAN2_DGRAM_LT_HDR, raw_pkt, len);
        return false;
    }

    if (p->encapsulated)
    {
        /* discard packet - multiple encapsulation */
        /* not sure if this is ever used but I am assuming it is not */
        CodecEvents::decoder_alert_encapsulated(p, DECODE_IP_MULTIPLE_ENCAPSULATION,
                        raw_pkt, len);
        return false;
    }

    /* Check that this is in fact ERSpan Type 2.
     */
    if (ERSPAN_VERSION(erSpan2Hdr) != 0x01) /* Type 2 == version 0x01 */
    {
        CodecEvents::decoder_alert_encapsulated(p, DECODE_ERSPAN_HDR_VERSION_MISMATCH,
                        raw_pkt, len);
        return false;
    }


    next_prot_id = ETHERTYPE_TRANS_ETHER_BRIDGING; // huh?
    return true;
}



static void get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_ERSPAN_TYPE2);
}

static Codec* ctor()
{
    return new Erspan2Codec();
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



static const char* name = "erspan2_codec";

static const CodecApi erspan2_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
    nullptr,
    get_protocol_ids,
    sum, // sum
    stats  // stats
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &erspan2_api.base,
    nullptr
};
#else
const BaseApi* cd_erspan2 = &erspan2_api.base;
#endif
