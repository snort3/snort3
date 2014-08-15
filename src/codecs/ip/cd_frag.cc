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
#include "codecs/ip/ipv6_util.h"
#include "protocols/packet.h"


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

    virtual void get_protocol_ids(std::vector<uint16_t>&);
    
};


} // namespace


bool Ipv6FragCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    const IP6Frag* ip6frag_hdr = reinterpret_cast<const IP6Frag*>(raw_pkt);

    fpEvalIpProtoOnlyRules(snort_conf->ip_proto_only_lists, p, IPPROTO_ID_FRAGMENT);
    ipv6_util::CheckIPv6ExtensionOrder(p);

    if(raw_len < ipv6::min_ext_len() )
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
    if (raw_len == sizeof(IP6Frag))
    {
        codec_events::decoder_event(p, DECODE_ZERO_LENGTH_FRAG);
        return false;
    }

    /* If this is an IP Fragment, set some data... */
    p->ip6_frag_index = p->ip6_extension_count;
    p->ip_frag_start = raw_pkt + sizeof(IP6Frag);

    p->decode_flags &= ~DECODE__DF;

    if (ipv6::is_mf_set(ip6frag_hdr))
        p->decode_flags |= DECODE__MF;

    if (ipv6::is_res_set(ip6frag_hdr))
        p->decode_flags |= DECODE__RF;

    // three least signifigant bits are all flags
    p->frag_offset = ntohs(ip6frag_hdr->get_off()) >> 3;
    if (p->frag_offset || (p->decode_flags & DECODE__MF))
    {
        p->decode_flags |= DECODE__FRAG;
    }
    else
    {
        codec_events::decoder_event(p, DECODE_IPV6_BAD_FRAG_PKT);
    }
    if (!(p->frag_offset))
    {
        // check header ordering of fragged (next) header
        if ( ipv6_util::IPV6ExtensionOrder(ip6frag_hdr->ip6f_nxt) <
             ipv6_util::IPV6ExtensionOrder(IPPROTO_FRAGMENT) )
            codec_events::decoder_event(p, DECODE_IPV6_UNORDERED_EXTENSIONS);
    }

    // check header ordering up thru frag header
    ipv6_util::CheckIPv6ExtensionOrder(p);

    lyr_len = sizeof(IP6Frag);
    p->ip_frag_len = (uint16_t)(raw_len - lyr_len);

    if ( (p->decode_flags & DECODE__FRAG) && ((p->frag_offset > 0) ||
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


    p->ip6_extensions[p->ip6_extension_count].type = IPPROTO_ID_FRAGMENT;
    p->ip6_extensions[p->ip6_extension_count].data = raw_pkt;
    p->ip6_extension_count++;

    next_prot_id = ip6frag_hdr->ip6f_nxt;
    return true;
}



void Ipv6FragCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ID_FRAGMENT);
}



//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{
    return new Ipv6FragCodec();
}

static void dtor(Codec *cd)
{
    delete cd;
}

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
