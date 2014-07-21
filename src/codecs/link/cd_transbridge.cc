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
// cd_transbridge.cc author Josh Rosenbaum <jrosenba@cisco.com>




#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"

#include "protocols/eth.h"
#include "protocols/protocol_ids.h"

namespace
{

#define CD_TRANSBRIDGE_NAME "cd_transbridge"

class TransbridgeCodec : public Codec
{
public:
    TransbridgeCodec() : Codec(CD_TRANSBRIDGE_NAME){};
    ~TransbridgeCodec(){};


    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
    
};

} // anonymous namespace


void TransbridgeCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_TRANS_ETHER_BRIDGING); // defined in ethertypes.h"
}


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
bool TransbridgeCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    if(raw_len < eth::hdr_len())
    {
        codec_events::decoder_alert_encapsulated(p, DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR,
                        raw_pkt, raw_len);
        return false;
    }

    /* The Packet struct's ethernet header will now point to the inner ethernet
     * header of the packet
     */
    const eth::EtherHdr *eh = reinterpret_cast<const eth::EtherHdr*>(raw_pkt);

    p->proto_bits |= PROTO_BIT__ETH;
    lyr_len = eth::hdr_len();
    next_prot_id = ntohs(eh->ether_type);

    return true;
}


//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{
    return new TransbridgeCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const CodecApi transbridge_api =
{
    {
        PT_CODEC,
        CD_TRANSBRIDGE_NAME,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    dtor, // dtor
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &transbridge_api.base,
    nullptr
};
#else
const BaseApi* cd_transbridge = &transbridge_api.base;
#endif




