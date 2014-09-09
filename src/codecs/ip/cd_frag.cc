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
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"
#include "protocols/ipv6.h"
#include "protocols/protocol_ids.h"
#include "main/snort.h"
#include "detection/fpdetect.h"
#include "codecs/ip/ip_util.h"
#include "protocols/packet.h"
#include "log/text_log.h"
#include "protocols/packet_manager.h"


namespace
{

#define CD_IPV6_FRAG_NAME "ipv6_frag"

class Ipv6FragCodec : public Codec
{
public:
    Ipv6FragCodec() : Codec(CD_IPV6_FRAG_NAME){};
    ~Ipv6FragCodec() {};


    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual void log(TextLog* const, const uint8_t* /*raw_pkt*/,
                    const Packet* const);
    virtual void get_protocol_ids(std::vector<uint16_t>&);
    
};


} // namespace


bool Ipv6FragCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    const ip::IP6Frag* ip6frag_hdr = reinterpret_cast<const ip::IP6Frag*>(raw_pkt);

    fpEvalIpProtoOnlyRules(snort_conf->ip_proto_only_lists, p, IPPROTO_ID_FRAGMENT);

    if(raw_len < ip::MIN_EXT_LEN )
    {
        codec_events::decoder_event(p, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    if ( p->ip6_extension_count >= IP6_EXTMAX )
    {
        codec_events::decoder_event(p, DECODE_IP6_EXCESS_EXT_HDR);
        return false;
    }

    // already checked for short pacekt above
    if (raw_len == sizeof(ip::IP6Frag))
    {
        codec_events::decoder_event(p, DECODE_ZERO_LENGTH_FRAG);
        return false;
    }

    /* If this is an IP Fragment, set some data... */
    p->ip6_frag_index = p->num_layers;
    p->decode_flags &= ~DECODE__DF;

    if (ntohs(ip6frag_hdr->ip6f_offlg) & ip::IP6F_MF_MASK)
        p->decode_flags |= DECODE__MF;

#if 0
    // reserved flag currently not used
    if (ip6frag_hdr->get_res() != 0)))
        p->decode_flags |= DECODE__RF;
#endif

    // three least signifigant bits are all flags
    const uint16_t frag_offset =  ntohs(ip6frag_hdr->get_off()) >> 3;
    if (frag_offset || (p->decode_flags & DECODE__MF))
    {
        p->decode_flags |= DECODE__FRAG;
    }
    else
    {
        codec_events::decoder_event(p, DECODE_IPV6_BAD_FRAG_PKT);
    }
    if (!(frag_offset))
    {
        // check header ordering of fragged (next) header
        if ( ip_util::IPV6ExtensionOrder(ip6frag_hdr->ip6f_nxt) <
             ip_util::IPV6ExtensionOrder(IPPROTO_FRAGMENT) )
            codec_events::decoder_event(p, DECODE_IPV6_UNORDERED_EXTENSIONS);
    }


    lyr_len = sizeof(ip::IP6Frag);
    next_prot_id = ip6frag_hdr->ip6f_nxt;

    // check header ordering up thru frag header
    ip_util::CheckIPv6ExtensionOrder(p, IPPROTO_ID_FRAGMENT, next_prot_id);

    if ( (p->decode_flags & DECODE__FRAG) && ((frag_offset > 0) ||
         (ip6frag_hdr->ip6f_nxt != IPPROTO_UDP)) )
    {
        /* For non-zero offset frags, we stop decoding after the
           Frag header. According to RFC 2460, the "Next Header"
           value may differ from that of the offset zero frag,
           but only the Next Header of the original frag is used. */
        // check DecodeIP(); we handle frags the same way here
        p->ip6_extension_count++;
        return false;
    }

    p->ip6_extension_count++;
    return true;
}



void Ipv6FragCodec::get_protocol_ids(std::vector<uint16_t>& v)
{ v.push_back(IPPROTO_ID_FRAGMENT); }


void Ipv6FragCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
                    const Packet* const)
{
    const ip::IP6Frag* fragh = reinterpret_cast<const ip::IP6Frag*>(raw_pkt);
    const uint16_t offlg = ntohs(fragh->get_off());


    TextLog_Print(text_log, "Next:0x%02X Off:%u ID:%u",
            fragh->ip6f_nxt, (offlg >> 3), ntohl(fragh->get_id()));

    if (offlg & ip::IP6F_MF_MASK)
        TextLog_Puts(text_log, " MF");
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new Ipv6FragCodec(); }

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi ipv6_frag_api =
{
    {
        PT_CODEC,
        CD_IPV6_FRAG_NAME,
        CDAPI_PLUGIN_V0,
        0,
        nullptr,
        nullptr,
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
    &ipv6_frag_api.base,
    nullptr
};
#else
const BaseApi* cd_frag = &ipv6_frag_api.base;
#endif
