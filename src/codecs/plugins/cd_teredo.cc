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
// cd_teredo.cc author Josh Rosenbaum <jorosenba@cisco.com>




#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

//#include "generators.h"
//#include "decode.h"  
//#include "static_include.h"

//#include "prot_ipv6.h"

#include "snort_types.h"
#include "protocols/packet.h"
#include "snort.h"
#include "snort_config.h"
#include "packet_io/active.h"
#include "protocols/ipv6.h"
#include "protocols/teredo.h"
#include "protocols/undefined_protocols.h"

namespace
{

class TeredoCodec : public Codec
{
public:
    TeredoCodec() : Codec("teredo"){};
    ~TeredoCodec(){};

    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &lyr_len, int &next_prot_id);
};

} // anonymous namespace


void TeredoCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(PROTOCOL_TEREDO);
}


bool TeredoCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &lyr_len, int &next_prot_id)
{


    if (len < teredo::min_hdr_len())
        return false;

    /* Decode indicators. If both are present, Auth always comes before Origin. */
    if (ntohs(*(uint16_t *)raw_pkt) == teredo::inidicator_auth())
    {
        uint8_t client_id_length, auth_data_length;

        if (len < teredo::min_indicator_auth_len())
            return false;

        client_id_length = *(raw_pkt + 2);
        auth_data_length = *(raw_pkt + 3);

        if (len < (uint32_t)(teredo::min_indicator_auth_len() + client_id_length + auth_data_length))
            return false;

        lyr_len = (teredo::min_indicator_auth_len() + client_id_length + auth_data_length);
    }

    if (ntohs(*(uint16_t *)raw_pkt) == teredo::indicator_origin())
    {
        if (len < teredo::indicator_origin_len())
            return false;

        lyr_len += teredo::indicator_origin_len();
    }

    /* If this is an IPv6 datagram, the first 4 bits will be the number 6. */
    if (( (*raw_pkt & 0xF0) >> 4) == 6)
    {
        p->proto_bits |= PROTO_BIT__TEREDO;
//        dc.teredo++;

        if ( ScTunnelBypassEnabled(TUNNEL_TEREDO) )
            Active_SetTunnelBypass();

        if (ScDeepTeredoInspection() && (!teredo::is_teredo_port(p->sp)) && (!teredo::is_teredo_port(p->dp)))
            p->packet_flags |= PKT_UNSURE_ENCAP;

        next_prot_id = IPPROTO_IPV6;
//        DecodeIPV6(pkt, len, p);
//        p->packet_flags &= ~PKT_UNSURE_ENCAP;
        return true;
    }

    /* Otherwise, we treat this as normal UDP traffic. */
    return false;
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor()
{
    return new TeredoCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const char* name = "teredo";
static const CodecApi teredo_api =
{
    {
        PT_CODEC,
        name,
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
    &teredo_api.base,
    nullptr
};
#else
const BaseApi* cd_teredo = &teredo_api.base;
#endif





