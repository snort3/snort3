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
// cd_ip4_embedded_in_icmp.cc author Josh Rosenbaum <jrosenba@cisco.com>



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
#ifndef IP4_EMBEDDED_IN_ICMP
#define IP4_EMBEDDED_IN_ICMP "ip4_embedded_in_icmp"
#endif

class Ip4EmbeddedInIcmpCodec : public Codec
{
public:
    Ip4EmbeddedInIcmpCodec() : Codec(IP4_EMBEDDED_IN_ICMP){};
    ~Ip4EmbeddedInIcmpCodec() {};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t &raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual void get_protocol_ids(std::vector<uint16_t>&);

};

} // namespace


void Ip4EmbeddedInIcmpCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IP_EMBEDDED_IN_ICMP4);
}

bool Ip4EmbeddedInIcmpCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet* p, uint16_t& lyr_len, uint16_t& next_prot_id)
{
    uint32_t ip_len;       /* length from the start of the ip hdr to the
                             * pkt end */
    uint32_t hlen;          /* ip header length */

    /* do a little validation */
    if(raw_len < ip::IP4_HEADER_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP: IP short header (%d bytes)\n", raw_len););

        codec_events::decoder_event(p, DECODE_ICMP_ORIG_IP_TRUNCATED);

        return false;
    }

    /* lay the IP struct over the raw data */
    const IPHdr *ip4h = reinterpret_cast<const IPHdr *>(raw_pkt);

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if((ip4h->get_ver() != 4) && !p->ip_api.is_ip6())
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP: not IPv4 datagram ([ver: 0x%x][len: 0x%x])\n",
            ip4h->get_ver(), ntohs(ip4h->get_len())););

        codec_events::decoder_event(p, DECODE_ICMP_ORIG_IP_VER_MISMATCH);

        return false;
    }

    ip_len = ntohs(ip4h->get_len());/* set the IP datagram length */
    hlen = ip4h->get_hlen() << 2;    /* set the IP header length */

    if(raw_len < hlen)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "ICMP: IP len (%d bytes) < IP hdr len (%d bytes), packet discarded\n",
            ip_len, hlen););

        codec_events::decoder_event(p, DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP);
        return false;
    }

    /* set the remaining packet length */
    ip_len = raw_len - hlen;

    uint16_t orig_frag_offset = ntohs(ip4h->get_off());
    orig_frag_offset &= 0x1FFF;

    if (orig_frag_offset == 0)
    {
        /* Original IP payload should be 64 bits */
        if (ip_len < 8)
        {
            codec_events::decoder_event(p, DECODE_ICMP_ORIG_PAYLOAD_LT_64);

            return false;
        }
        /* ICMP error packets could contain as much of original payload
         * as possible, but not exceed 576 bytes
         */
        else if (ntohs(p->ip_api.len()) > 576)
        {
            codec_events::decoder_event(p, DECODE_ICMP_ORIG_PAYLOAD_GT_576);
        }
    }
    else
    {
        /* RFC states that only first frag will get an ICMP response */
        codec_events::decoder_event(p, DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET);
        return false;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP Unreachable IP header length: "
                            "%lu\n", (unsigned long)hlen););

    // since we know the protocol ID in this layer (and NOT the
    // next layer), set the correct protocol here.  Normally,
    // I would just set the next_protocol_id and let the packet_manger
    // decode the next layer. However, I  can't set the next_prot_id in
    // this case because I don't want this going to the TCP, UDP, or
    // ICMP codec. Therefore, doing a minor decode here.
    switch(ip4h->get_proto())
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

    lyr_len = ip::IP4_HEADER_LEN;
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Codec* ctor(Module*)
{
    return new Ip4EmbeddedInIcmpCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}


static const CodecApi ip4_embedded_in_icmp_api =
{
    {
        PT_CODEC,
        IP4_EMBEDDED_IN_ICMP,
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
    &ip4_embedded_in_icmp_api.base,
    nullptr
};
#else
const BaseApi* cd_ip4_embedded_in_icmp = &ip4_embedded_in_icmp_api.base;
#endif
