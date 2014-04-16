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

namespace
{

class TeredoCodec : public Codec
{
public:
    TeredoCodec() : Codec("teredo"){};
    ~TeredoCodec();


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *, uint16_t &p_hdr_len, int &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    
};

} // anonymous namespace

bool TeredoCodec::decode(const uint8_t *raw_pkt, const uint32_t len, 
        Packet *p, uint16_t &p_hdr_len, int &next_prot_id)
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

        p_hdr_len = (teredo::min_indicator_auth_len() + client_id_length + auth_data_length);
    }

    if (ntohs(*(uint16_t *)raw_pkt) == teredo::indicator_origin())
    {
        if (len < teredo::indicator_origin_len())
            return false;

        p_hdr_len += teredo::indicator_origin_len();
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



void TeredoCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(teredo::teredo_id());
}

static Codec* ctor()
{
    return new TeredoCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

static const char* name = "teredo_codec";

static const CodecApi ipv6_api =
{
    { PT_CODEC, name, CDAPI_PLUGIN_V0, 0 },
    NULL, // pinit
    NULL, // pterm
    NULL, // tinit
    NULL, // tterm
    ctor, // ctor
    dtor, // dtor
};


