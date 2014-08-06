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
// cd_ip6_embedded_in_icmp.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "protocols/ipv4.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"


namespace
{

// yes, macros are necessary. The API and class constructor require different strings.
//
// this macros is defined in the module to ensure identical names. However,
// if you don't want a module, define the name here.
#ifndef IP6_EMBEDDED_IN_ICMP
#define IP6_EMBEDDED_IN_ICMP "ip6_embedded_in_icmp"
#endif

class Ip6EmbeddedInIcmpCodec : public Codec
{
public:
    Ip6EmbeddedInIcmpCodec() : Codec(IP6_EMBEDDED_IN_ICMP){};
    ~Ip6EmbeddedInIcmpCodec() {};


    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t &raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);
};

} // namespace

// TODO: delete
#include <iostream>

void Ip6EmbeddedInIcmpCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IP_EMBEDDED_IN_ICMP6);
}

bool Ip6EmbeddedInIcmpCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet* p, uint16_t& lyr_len, uint16_t& next_prot_id)
{
//    uint16_t orig_frag_offset;

    /* lay the IP struct over the raw data */
    const ipv6::IP6RawHdr* ip6h = reinterpret_cast<const ipv6::IP6RawHdr*>(raw_pkt);

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "DecodeICMPEmbeddedIP6: ip header"
                    " starts at: %p, length is %lu\n", ip6h,
                    (unsigned long) raw_len););

    /* do a little validation */
    if ( raw_len < ipv6::hdr_len() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP6: IP short header (%d bytes)\n", raw_len););

        codec_events::decoder_event(p, DECODE_ICMP_ORIG_IP_TRUNCATED);

        return false;
    }

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if(ip6h->get_ver() != 6)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP: not IPv6 datagram ([ver: 0x%x][len: 0x%x])\n",
            ip6h->get_ver(), raw_len););

        codec_events::decoder_event(p, DECODE_ICMP_ORIG_IP_VER_MISMATCH);

        return false;
    }

    if ( raw_len < ipv6::hdr_len() )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP6: IP6 len (%d bytes) < IP6 hdr len (%d bytes), packet discarded\n",
            raw_len, ipv6::hdr_len()););

        codec_events::decoder_event(p, DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP);

        return false;
    }

//    orig_frag_offset = ntohs(GET_ORIG_IPH_OFF(p));
//    orig_frag_offset &= 0x1FFF;

    // XXX NOT YET IMPLEMENTED - fragments inside ICMP payload

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP6 Unreachable IP6 header length: "
                            "%lu\n", (unsigned long)ipv6::hdr_len()););

    // since we know the protocol ID in this layer (and NOT the
    // next layer), set the correct protocol here.  Normally,
    // I would just set the next_protocol_id and let the packet_manger
    // decode the next layer. However, I  can't set the next_prot_id in
    // this case because I don't want this going to the TCP, UDP, or
    // ICMP codec. Therefore, doing a minor decode here.
    switch(ip6h->get_next())
    {
        case IPPROTO_TCP: /* decode the interesting part of the header */
            p->proto_bits |= PROTO_BIT__TCP_EMBED_ICMP;
            next_prot_id = PROT_EMBEDDED_IN_ICMP;
            break;

        case IPPROTO_UDP:
            p->proto_bits |= PROTO_BIT__UDP_EMBED_ICMP;
            next_prot_id = PROT_EMBEDDED_IN_ICMP;
            break;

        case IPPROTO_ICMP:
            p->proto_bits |= PROTO_BIT__ICMP_EMBED_ICMP;
            next_prot_id = PROT_EMBEDDED_IN_ICMP;
            break;
    }

    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{
    return new Ip6EmbeddedInIcmpCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const CodecApi ip6_embedded_in_icmp_api =
{
    {
        PT_CODEC,
        IP6_EMBEDDED_IN_ICMP,
        CDAPI_PLUGIN_V0,
        0,
        nullptr, // module constructor
        nullptr  // module destructor
    },
    nullptr, // g_ctor
    nullptr, // g_dtor
    nullptr, // t_ctor
    nullptr, // t_dtor
    ctor,
    dtor,
};


#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &name_api.base,
    nullptr
};
#else
const BaseApi* cd_ip6_embedded_in_icmp = &ip6_embedded_in_icmp_api.base;
#endif
