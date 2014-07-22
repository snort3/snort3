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
// cd_arp.cc author Josh Rosenbaum <jrosenba@cisco.com>






#include "framework/codec.h"
#include "codecs/link/cd_arp_module.h"
#include "codecs/codec_events.h"
#include "protocols/protocol_ids.h"
#include "codecs/sf_protocols.h"
#include "protocols/arp.h"

namespace
{

class ArpCodec : public Codec
{
public:
    ArpCodec() : Codec(CD_ARP_NAME){};
    ~ArpCodec(){};


    virtual PROTO_ID get_proto_id() { return PROTO_ARP; };
    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, uint16_t &);
    
};


} // anonymous namespace



void ArpCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_ARP);
    v.push_back(ETHERTYPE_REVARP);
}


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
bool ArpCodec::decode(const uint8_t* /*raw_pkt*/, const uint32_t len,
        Packet *p, uint16_t &lyr_len, uint16_t& /* next_prot_id */)
{
    if(len < sizeof(EtherARP))
    {
        codec_events::decoder_event(p, DECODE_ARP_TRUNCATED);
        return false;
    }

    p->proto_bits |= PROTO_BIT__ARP;
    lyr_len = sizeof(EtherARP);
    
    return true;
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ArpModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Codec* ctor(Module*)
{
    return new ArpCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const CodecApi arp_api =
{
    {
        PT_CODEC,
        CD_ARP_NAME,
        CDAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor,
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    dtor, // dtor
};

const BaseApi* cd_arp = &arp_api.base;
