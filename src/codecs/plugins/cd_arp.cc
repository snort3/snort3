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
// cd_arp.cc author Josh Rosenbaum <jorosenba@cisco.com>






#include "framework/codec.h"
#include "codecs/decode_module.h"
#include "events/codec_events.h"

namespace
{

class ArpCodec : public Codec
{
public:
    ArpCodec() : Codec("Arp"){};
    ~ArpCodec(){};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, int &next_prot_id);
    

    // DELETE from here and below
    #include "codecs/sf_protocols.h"
    virtual inline PROTO_ID get_proto_id() { return PROTO_ARP; };
};


static const uint16_t ETHERNET_TYPE_REVARP = 0x8035;
static const uint16_t ETHERNET_TYPE_ARP = 0x0806;
} // anonymous namespace




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
bool ArpCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &lyr_len, int &next_prot_id)
{
//    dc.arp++;

//    if (p->greh != NULL)
//        dc.gre_arp++;

    p->ah = (EtherARP *) raw_pkt;

    if(len < sizeof(EtherARP))
    {
        codec_events::decoder_event(p, DECODE_ARP_TRUNCATED);

//        dc.discards++;
        return false;
    }

    p->proto_bits |= PROTO_BIT__ARP;
    lyr_len = sizeof(*p->ah);
    next_prot_id = -1;

    return true;
}




static void get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERNET_TYPE_ARP);
    v.push_back(ETHERNET_TYPE_REVARP);
}

static Codec* ctor()
{
    return new ArpCodec();
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



static const char* name = "arp_codec";
static const CodecApi arp_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
    NULL, // get_dlt
    get_protocol_ids,
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &arp_api.base,
    nullptr
};
#else
const BaseApi* cd_arp = &arp_api.base;
#endif




