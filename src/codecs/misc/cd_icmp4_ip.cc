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
#include "protocols/packet.h"
#include "codecs/codec_events.h"


namespace
{

// yes, macros are necessary. The API and class constructor require different strings.
//
// this macros is defined in the module to ensure identical names. However,
// if you don't want a module, define the name here.
#ifndef ICMP4_IP_NAME
#define ICMP4_IP_NAME "icmp4_ip"
#endif

class Icmp4IpCodec : public Codec
{
public:
    Icmp4IpCodec() : Codec(ICMP4_IP_NAME){};
    ~Icmp4IpCodec() {};


    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual bool encode(EncState* enc, Buffer* out, const uint8_t* raw_in);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t &raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);


};

} // namespace


void Icmp4IpCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IP_EMBEDDED_IN_ICMP4);
}

bool Icmp4IpCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet* p, uint16_t& lyr_len, uint16_t& /*next_prot_id*/)
{
    uint32_t ip_len;       /* length from the start of the ip hdr to the
                             * pkt end */
    uint32_t hlen;          /* ip header length */

    /* do a little validation */
    if(raw_len < ip::IP4_HEADER_LEN)
    {
        codec_events::decoder_event(p, DECODE_ICMP_ORIG_IP_TRUNCATED);
        return false;
    }

    /* lay the IP struct over the raw data */
    const IP4Hdr *ip4h = reinterpret_cast<const IP4Hdr *>(raw_pkt);

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if((ip4h->get_ver() != 4) && !p->ip_api.is_ip6())
    {
        codec_events::decoder_event(p, DECODE_ICMP_ORIG_IP_VER_MISMATCH);
        return false;
    }

    ip_len = ntohs(ip4h->get_len());/* set the IP datagram length */
    hlen = ip4h->get_hlen() << 2;    /* set the IP header length */

    if(raw_len < hlen)
    {
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
            break;

        case IPPROTO_UDP:
            p->proto_bits |= PROTO_BIT__UDP_EMBED_ICMP;
            break;

        case IPPROTO_ICMP:
            p->proto_bits |= PROTO_BIT__ICMP_EMBED_ICMP;
            break;
    }

    // If you change this, change the buffer and
    // memcpy length in encode() below !!
    lyr_len = ip::IP4_HEADER_LEN;
    return true;
}


bool Icmp4IpCodec::encode(EncState* /*enc*/, Buffer* out, const uint8_t* raw_in)
{
    // allocate space for this protocols encoded data
    if (!update_buffer(out, ip::IP4_HEADER_LEN))
        return false;

    memcpy(out->base, raw_in, ip::IP4_HEADER_LEN);
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Codec* ctor(Module*)
{ return new Icmp4IpCodec(); }

static void dtor(Codec *cd)
{ delete cd; }


static const CodecApi icmp4_ip_api =
{
    {
        PT_CODEC,
        ICMP4_IP_NAME,
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
    &icmp4_ip_api.base,
    nullptr
};
#else
const BaseApi* cd_icmp4_ip = &icmp4_ip_api.base;
#endif
