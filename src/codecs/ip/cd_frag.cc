//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// cd_frag.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/text_log.h"
#include "main/snort_config.h"

using namespace snort;

#define CD_IPV6_FRAG_NAME "ipv6_frag"
#define CD_IPV6_FRAG_HELP "support for IPv6 fragment decoding"

namespace
{
class Ipv6FragCodec : public Codec
{
public:
    Ipv6FragCodec() : Codec(CD_IPV6_FRAG_NAME) { }

    bool decode(const RawData&, CodecData&, DecodeData&) override;

    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
    void get_protocol_ids(std::vector<ProtocolId>&) override;
};
} // namespace

bool Ipv6FragCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    const ip::IP6Frag* const ip6frag_hdr = reinterpret_cast<const ip::IP6Frag*>(raw.data);

    if (raw.len < ip::MIN_EXT_LEN )
    {
        codec_event(codec, DECODE_IPV6_TRUNCATED_EXT);
        return false;
    }

    if ( SnortConfig::get_conf()->hit_ip6_maxopts(codec.ip6_extension_count) )
    {
        codec_event(codec, DECODE_IP6_EXCESS_EXT_HDR);
        return false;
    }

    // already checked for short packet above
    if (raw.len == sizeof(ip::IP6Frag))
    {
        // FIXIT-L  identical to DEFRAG_ANOMALY_ZERO.  Commenting
        // 'return false' so that it has the same functionality as IPv4
        codec_event(codec, DECODE_ZERO_LENGTH_FRAG);
//        return false;
    }

    /* If this is an IP Fragment, set some data... */
    codec.codec_flags &= ~CODEC_DF;

    if (ip6frag_hdr->mf())
        snort.decode_flags |= DECODE_MF;

#if 0
    // reserved flag currently not used
    if (ip6frag_hdr->get_res() != 0)
        data.decode_flags |= DECODE_RF;
#endif

    // three least significant bits are all flags
    const uint16_t frag_offset = ip6frag_hdr->off();

    if (frag_offset || (snort.decode_flags & DECODE_MF))
        snort.decode_flags |= DECODE_FRAG;
    else
        codec_event(codec, DECODE_IPV6_BAD_FRAG_PKT);

    codec.lyr_len = sizeof(ip::IP6Frag);
    codec.ip6_csum_proto = ip6frag_hdr->ip6f_nxt;
    codec.proto_bits |= PROTO_BIT__IP6_EXT;
    codec.ip6_extension_count++;

    // FIXIT-H the comment says to call it after setting next_prot_id,
    // but it looks like it's called (twice) before setting it.

    // must be called AFTER setting next_prot_id
    CheckIPv6ExtensionOrder(codec, IpProtocol::FRAGMENT);

    // FIXIT-H this breaks the tests/ips/normalize/ip6/would_opts_nop test
    // because ip6frag_hdr->ip6f_nxt is set to FINISHED_DECODE here.  (or
    // maybe the test has the wrong expected data).

    // Since the Frag layer is removed from rebuilt packets, ensure
    // the next layer is correctly order now.
    if (frag_offset == 0)
        CheckIPv6ExtensionOrder(codec, ip6frag_hdr->ip6f_nxt);

    if ( snort.decode_flags & DECODE_FRAG )
    {
        /* For non-zero offset frags, we stop decoding after the
           Frag header. According to RFC 2460, the "Next Header"
           value may differ from that of the offset zero frag,
           but only the Next Header of the original frag is used. */
        // check DecodeIP(); we handle frags the same way here
        codec.next_prot_id = ProtocolId::FINISHED_DECODE;
    }
    else
    {
        codec.next_prot_id = (ProtocolId)ip6frag_hdr->ip6f_nxt;
    }

    return true;
}

void Ipv6FragCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::FRAGMENT); }

void Ipv6FragCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
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

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi ipv6_frag_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_IPV6_FRAG_NAME,
        CD_IPV6_FRAG_HELP,
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
#else
const BaseApi* cd_frag[] =
#endif
{
    &ipv6_frag_api.base,
    nullptr
};

