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

#include "protocols/eth.h"
#include "protocols/ethertypes.h"

namespace
{

class TransbridgeCodec : public Codec
{
public:
    TransbridgeCodec() : Codec("Transbridge"){};
    ~TransbridgeCodec();


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &p_hdr_len, int &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    
};

} // anonymous namespace




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
bool TransbridgeCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &p_hdr_len, int &next_prot_id)
{
//    dc.gre_eth++;

    if(len < eth::hdr_len())
    {
        CodecEvents::decoder_alert_encapsulated(p, DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR,
                        raw_pkt, len);
        return false;
    }

    /* The Packet struct's ethernet header will now point to the inner ethernet
     * header of the packet
     */
    p->eh = (eth::EtherHdr *)raw_pkt;

    p_hdr_len = eth::hdr_len();
    next_prot_id = ntohs(p->eh->ether_type);

    return true;
}



void TransbridgeCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(TRANS_ETHER_BRIDGING_ETHERTYPE); // defined in ethertypes.h"
}

static Codec* ctor()
{
    return new TransbridgeCodec();
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



static const char* name = "transbridge_codec";

static const CodecApi transbridge_api =
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




