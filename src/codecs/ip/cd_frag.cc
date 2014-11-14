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
#include "codecs/codec_module.h"
#include "codecs/codec_events.h"
#include "protocols/ipv6.h"
#include "protocols/protocol_ids.h"
#include "main/snort.h"
#include "detection/fpdetect.h"
#include "codecs/ip/ip_util.h"
#include "protocols/packet.h"
#include "log/text_log.h"
#include "protocols/packet_manager.h"

#define CD_IPV6_FRAG_NAME "ipv6_frag"
#define CD_IPV6_FRAG_HELP "support for IPv6 fragment decoding"

namespace
{

class Ipv6FragCodec : public Codec
{
public:
    Ipv6FragCodec() : Codec(CD_IPV6_FRAG_NAME){};
    ~Ipv6FragCodec() {};


    bool decode(const RawData&, CodecData&, DecodeData&) override;

    void log(TextLog* const, const uint8_t* /*raw_pkt*/,
                    const Packet* const) override;
    void get_protocol_ids(std::vector<uint16_t>&) override;
    
};


} // namespace


bool Ipv6FragCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    const ip::IP6Frag* const ip6frag_hdr = reinterpret_cast<const ip::IP6Frag*>(raw.data);

    if(raw.len < ip::MIN_EXT_LEN )
    {
        codec_events::decoder_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    if ( codec.ip6_extension_count >= snort_conf->get_ip6_maxopts() )
    {
        codec_events::decoder_event(codec, DECODE_IP6_EXCESS_EXT_HDR);
        return false;
    }

    // already checked for short packet above
    if (raw.len == sizeof(ip::IP6Frag))
    {
        // FIXIT-L  identical to DEFRAG_ANOMALY_ZERO.  Commenting
        // 'return false' so that it has the same functionality as IPv4
        codec_events::decoder_event(codec, DECODE_ZERO_LENGTH_FRAG);
//        return false;
    }

    /* If this is an IP Fragment, set some data... */
    codec.codec_flags &= ~CODEC_DF;

    if (ip6frag_hdr->mf())
        snort.decode_flags |= DECODE_MF;

#if 0
    // reserved flag currently not used
    if (ip6frag_hdr->get_res() != 0)))
        data.decode_flags |= DECODE_RF;
#endif

    // three least signifigant bits are all flags
    const uint16_t frag_offset = ip6frag_hdr->off();

    if (frag_offset || (snort.decode_flags & DECODE_MF))
        snort.decode_flags |= DECODE_FRAG;
    else
        codec_events::decoder_event(codec, DECODE_IPV6_BAD_FRAG_PKT);


    codec.lyr_len = sizeof(ip::IP6Frag);
    codec.ip6_csum_proto = ip6frag_hdr->ip6f_nxt;
    codec.proto_bits |= PROTO_BIT__IP6_EXT;
    codec.ip6_extension_count++;

    // must be called AFTER setting next_prot_id
    ip_util::CheckIPv6ExtensionOrder(codec, IPPROTO_ID_FRAGMENT);

    // Since the Frag layer is removed from rebuilt packets, ensure
    // the next layer is correctly order now.
    if (frag_offset == 0)
        ip_util::CheckIPv6ExtensionOrder(codec, ip6frag_hdr->ip6f_nxt);

    if ( snort.decode_flags & DECODE_FRAG )
    {
        /* For non-zero offset frags, we stop decoding after the
           Frag header. According to RFC 2460, the "Next Header"
           value may differ from that of the offset zero frag,
           but only the Next Header of the original frag is used. */
        // check DecodeIP(); we handle frags the same way here
        codec.next_prot_id = FINISHED_DECODE;

    }
    else
    {
        codec.next_prot_id = ip6frag_hdr->ip6f_nxt;
    }

    return true;
}



void Ipv6FragCodec::get_protocol_ids(std::vector<uint16_t>& v)
{ v.push_back(IPPROTO_ID_FRAGMENT); }


void Ipv6FragCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
                    const Packet* const)
{
    const ip::IP6Frag* fragh = reinterpret_cast<const ip::IP6Frag*>(raw_pkt);
    const uint16_t offlg = fragh->off();


    TextLog_Print(text_log, "Next:0x%02X Off:%u ID:%u",
            fragh->ip6f_nxt, offlg, fragh->id());

    if (fragh->mf())
        TextLog_Puts(text_log, " MF");

    if (fragh->rb())
        TextLog_Puts(text_log, " RB");
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
        CD_IPV6_FRAG_HELP,
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
