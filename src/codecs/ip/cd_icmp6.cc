//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
// cd_icmp6.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <daq.h>

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "protocols/icmp6.h"
#include "protocols/icmp4.h"
#include "utils/util.h"

#include "checksum.h"

using namespace snort;

#define CD_ICMP6_NAME "icmp6"
#define CD_ICMP6_HELP "support for Internet control message protocol v6"

namespace
{
const PegInfo pegs[]
{
    { CountType::SUM, "bad_icmp6_checksum", "nonzero icmp6 checksums" },
    { CountType::SUM, "checksum_bypassed", "checksum calculations bypassed" },
    { CountType::END, nullptr, nullptr }
};

struct Stats
{
    PegCount bad_ip6_cksum;
    PegCount cksum_bypassed;
};

static THREAD_LOCAL Stats stats;

static const RuleMap icmp6_rules[] =
{
    { DECODE_ICMP6_HDR_TRUNC, "truncated ICMPv6 header" },
    { DECODE_ICMP6_TYPE_OTHER, "ICMPv6 type not decoded" },
    { DECODE_ICMP6_DST_MULTICAST, "ICMPv6 packet to multicast address" },
    { DECODE_ICMPV6_TOO_BIG_BAD_MTU,
      "ICMPv6 packet of type 2 (message too big) with MTU field < 1280" },
    { DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE,
      "ICMPv6 packet of type 1 (destination unreachable) with non-RFC 2463 code" },
    { DECODE_ICMPV6_SOLICITATION_BAD_CODE,
      "ICMPv6 router solicitation packet with a code not equal to 0" },
    { DECODE_ICMPV6_ADVERT_BAD_CODE,
      "ICMPv6 router advertisement packet with a code not equal to 0" },
    { DECODE_ICMPV6_SOLICITATION_BAD_RESERVED,
      "ICMPv6 router solicitation packet with the reserved field not equal to 0" },
    { DECODE_ICMPV6_ADVERT_BAD_REACHABLE,
      "ICMPv6 router advertisement packet with the reachable time field set > 1 hour" },
    { DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE,
      "ICMPv6 packet of type 1 (destination unreachable) with non-RFC 4443 code" },
    { DECODE_ICMPV6_NODE_INFO_BAD_CODE,
      "ICMPv6 node info query/response packet with a code greater than 2" },
    { DECODE_ICMP6_NOT_IP6, "ICMPv6 not encapsulated in IPv6" },
    { DECODE_ICMP6_OPT_ZERO_LENGTH, "ICMPv6 option length field is set to 0" },
    { 0, nullptr }
};

class Icmp6Module : public BaseCodecModule
{
public:
    Icmp6Module() : BaseCodecModule(CD_ICMP6_NAME, CD_ICMP6_HELP) { }

    const RuleMap* get_rules() const override
    { return icmp6_rules; }

    const PegInfo* get_pegs() const override
    { return pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&stats; }
};

class Icmp6Codec : public Codec
{
public:
    Icmp6Codec() : Codec(CD_ICMP6_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
        uint16_t lyr_len, uint32_t& updated_len) override;
    void format(bool reverse, uint8_t* raw_pkt, DecodeData& snort) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;

private:
    bool valid_checksum_from_daq(const RawData&);
    template<typename OptionType>
    inline void validate_ndp_option(CodecData &codec, const OptionType* const icmp_pkt,
        const uint16_t min_len, const uint16_t dsize);
};
} // anonymous namespace

void Icmp6Codec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.emplace_back(ProtocolId::ICMPV6); }

inline bool Icmp6Codec::valid_checksum_from_daq(const RawData& raw)
{
    const DAQ_PktDecodeData_t* pdd =
        (const DAQ_PktDecodeData_t*) daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_DECODE_DATA);
    if (!pdd || !pdd->flags.bits.l4_checksum || !pdd->flags.bits.icmp || !pdd->flags.bits.l4)
        return false;
    // Sanity check to make sure we're talking about the same thing if offset is available
    if (pdd->l4_offset != DAQ_PKT_DECODE_OFFSET_INVALID)
    {
        const uint8_t* data = daq_msg_get_data(raw.daq_msg);
        if (raw.data - data != pdd->l4_offset)
            return false;
    }
    stats.cksum_bypassed++;
    return true;
}

template <typename NDPType>
void Icmp6Codec::validate_ndp_option(CodecData &codec, const NDPType* const icmp_pkt,
    const uint16_t min_len, const uint16_t dsize)
{
    const uint16_t real_size = dsize + icmp::ICMP6_HEADER_MIN_LEN;
    bool option_field_not_exists = real_size == min_len;
    if (option_field_not_exists)
        return;

    assert(real_size > min_len - icmp::ICMP6_HEADER_MIN_LEN);
    // Based on RFC2461, for types 133-137, "option" field depends on version
    // of implementation, so there's no unified format for all types.
    assert(icmp_pkt->type >= 133 && icmp_pkt->type <= 137);

    const uint8_t* const icmp_pkt_ptr = (const uint8_t* const)icmp_pkt;
    const uint8_t* curr_option_ptr = (const uint8_t* const)&icmp_pkt->options_start;

    while (real_size > curr_option_ptr - icmp_pkt_ptr )
    {
        assert(curr_option_ptr > icmp_pkt_ptr);
        bool field_incomplete = real_size == curr_option_ptr - icmp_pkt_ptr + 1;
        if (field_incomplete)
            return;     // FIXIT-L good candidate for new builtin rule

        const icmp::NDPOptionFormatBasic* curr_option = (const icmp::NDPOptionFormatBasic*)curr_option_ptr;

        // Right now, only option types explicitly specified in RFC4861 are supported
        if (curr_option->type == 0 || curr_option->type > 5)
            return;     // FIXIT-L good candidate for non-supported option field

        if (curr_option->length == 0)
        {
            codec_event(codec, DECODE_ICMP6_OPT_ZERO_LENGTH);
            return;
        }

        curr_option_ptr += curr_option->length * 8;
    }
}

bool Icmp6Codec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    if (raw.len < icmp::ICMP6_HEADER_MIN_LEN)
    {
        codec_event(codec, DECODE_ICMP6_HDR_TRUNC);
        return false;
    }

    if ( !snort.ip_api.get_ip6h() /* FIXIT-L && verify prior layer == ip6 */ )
    {
        codec_event(codec, DECODE_ICMP6_NOT_IP6);
        return false;
    }

    const icmp::Icmp6Hdr* const icmp6h = reinterpret_cast<const icmp::Icmp6Hdr*>(raw.data);

    if ( snort::get_network_policy()->icmp_checksums() && !valid_checksum_from_daq(raw))
    {
        checksum::Pseudoheader6 ph6;
        const ip::IP6Hdr* const ip6h = snort.ip_api.get_ip6h();
        COPY4(ph6.hdr.sip, ip6h->get_src()->u6_addr32);
        COPY4(ph6.hdr.dip, ip6h->get_dst()->u6_addr32);
        ph6.hdr.zero = 0;
        ph6.hdr.protocol = codec.ip6_csum_proto;
        ph6.hdr.len = htons((uint16_t)raw.len);

        uint16_t csum = checksum::icmp_cksum((const uint16_t*)(icmp6h), raw.len, ph6);

        if (csum && !codec.is_cooked())
        {
            stats.bad_ip6_cksum++;
            snort.decode_flags |= DECODE_ERR_CKSUM_ICMP;
            return false;
        }
    }

    const uint16_t dsize = raw.len - icmp::ICMP6_HEADER_MIN_LEN;
    uint16_t len = icmp::ICMP6_HEADER_MIN_LEN;

    switch (icmp6h->type)
    {
    case icmp::Icmp6Types::ECHO_REQUEST:
    case icmp::Icmp6Types::ECHO_REPLY:
        if (dsize >= sizeof(ICMPHdr::icmp_hun.idseq))
        {
            len = icmp::ICMP6_HEADER_NORMAL_LEN;

            if ( snort.ip_api.get_ip6h()->is_dst_multicast() )
                codec_event(codec, DECODE_ICMP6_DST_MULTICAST);
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    case icmp::Icmp6Types::PACKET_TOO_BIG:
        if (dsize >= sizeof(icmp::ICMP6TooBig))
        {
            const icmp::ICMP6TooBig* too_big = (const icmp::ICMP6TooBig*)raw.data;

            if (ntohl(too_big->mtu) < 1280)
                codec_event(codec, DECODE_ICMPV6_TOO_BIG_BAD_MTU);

            len = icmp::ICMP6_HEADER_NORMAL_LEN;
            codec.next_prot_id = ProtocolId::IP_EMBEDDED_IN_ICMP6;
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    case icmp::Icmp6Types::TIME_EXCEEDED6:
    case icmp::Icmp6Types::PARAMETER_PROBLEM:
    case icmp::Icmp6Types::DESTINATION_UNREACHABLE:
        if (dsize >= 4)
        {
            if (icmp6h->type == icmp::Icmp6Types::DESTINATION_UNREACHABLE)
            {
                if (icmp6h->code == icmp::Icmp6Code::UNREACH_INVALID)     // UNREACH_INVALID == 2
                    codec_event(codec, DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE);

                else if (static_cast<uint8_t>(icmp6h->code) > 6)
                    codec_event(codec, DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE);
            }
            len = icmp::ICMP6_HEADER_NORMAL_LEN;
            codec.next_prot_id = ProtocolId::IP_EMBEDDED_IN_ICMP6;
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    case icmp::Icmp6Types::ROUTER_SOLICITATION:
        if (dsize >= (ICMPv6_RS_MIN_LEN - icmp::ICMP6_HEADER_MIN_LEN))
        {
            const icmp::ICMP6RouterSolicitation* rs = (const icmp::ICMP6RouterSolicitation*)raw.data;

            if (rs->code != 0)
                codec_event(codec, DECODE_ICMPV6_SOLICITATION_BAD_CODE);

            if (ntohl(rs->reserved) != 0)
                codec_event(codec, DECODE_ICMPV6_SOLICITATION_BAD_RESERVED);

            validate_ndp_option(codec, rs, ICMPv6_RS_MIN_LEN, dsize);
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    case icmp::Icmp6Types::ROUTER_ADVERTISEMENT:
        if (dsize >= (ICMPv6_RA_MIN_LEN - icmp::ICMP6_HEADER_MIN_LEN))
        {
            const icmp::ICMP6RouterAdvertisement* ra = (const icmp::ICMP6RouterAdvertisement*)raw.data;

            if (icmp6h->code != icmp::Icmp6Code::ADVERTISEMENT)
                codec_event(codec, DECODE_ICMPV6_ADVERT_BAD_CODE);

            if (ntohl(ra->reachable_time) > 3600000)
                codec_event(codec, DECODE_ICMPV6_ADVERT_BAD_REACHABLE);

            validate_ndp_option(codec, ra, ICMPv6_RA_MIN_LEN, dsize);
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    case icmp::Icmp6Types::NEIGHBOR_SOLICITATION:
        if (dsize >= (ICMPv6_NS_MIN_LEN - icmp::ICMP6_HEADER_MIN_LEN))
        {
            const icmp::ICMP6NeighborSolicitation* ns = (const icmp::ICMP6NeighborSolicitation*)raw.data;

            validate_ndp_option(codec, ns, ICMPv6_NS_MIN_LEN, dsize);
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    case icmp::Icmp6Types::NEIGHBOR_ADVERTISEMENT:
        if (dsize >= (ICMPv6_NA_MIN_LEN - icmp::ICMP6_HEADER_MIN_LEN))
        {
            const icmp::ICMP6NeighborAdvertisement* na = (const icmp::ICMP6NeighborAdvertisement*)raw.data;

            validate_ndp_option(codec, na, ICMPv6_NA_MIN_LEN, dsize);
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    case icmp::Icmp6Types::REDIRECT6:
        if (dsize >= (ICMPv6_RD_MIN_LEN - icmp::ICMP6_HEADER_MIN_LEN))
        {
            const icmp::ICMP6Redirect* rd = (const icmp::ICMP6Redirect*)raw.data;

            validate_ndp_option(codec, rd, ICMPv6_RD_MIN_LEN, dsize);
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    case icmp::Icmp6Types::NODE_INFORMATION_QUERY:
    case icmp::Icmp6Types::NODE_INFORMATION_RESPONSE:
        if (dsize >= (sizeof(icmp::ICMP6NodeInfo) - icmp::ICMP6_HEADER_MIN_LEN))
        {
            const icmp::ICMP6NodeInfo* ni = (const icmp::ICMP6NodeInfo*)raw.data;
            if (ni->code > 2)
                codec_event(codec, DECODE_ICMPV6_NODE_INFO_BAD_CODE);

            // FIXIT-L add alert for INFO Response, code == 1 || code == 2) with data
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    // recognize these so we don't alert but no further checking (yet)
    case icmp::Icmp6Types::MULTICAST_LISTENER_QUERY:
    case icmp::Icmp6Types::MULTICAST_LISTENER_REPORT:
    case icmp::Icmp6Types::MULTICAST_LISTENER_DONE:
    case icmp::Icmp6Types::INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION:
    case icmp::Icmp6Types::INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT:
    case icmp::Icmp6Types::VERSION_2_MULTICAST_LISTENER_REPORT:
    case icmp::Icmp6Types::HOME_AGENT_ADDRESS_DISCOVERY_REQUEST:
    case icmp::Icmp6Types::HOME_AGENT_ADDRESS_DISCOVERY_REPLY:
    case icmp::Icmp6Types::MOBILE_PREFIX_SOLICITATION:
    case icmp::Icmp6Types::MOBILE_PREFIX_ADVERTISEMENT:
    case icmp::Icmp6Types::CERTIFICATION_PATH_SOLICITATION:
    case icmp::Icmp6Types::CERTIFICATION_PATH_ADVERTISEMENT:
    case icmp::Icmp6Types::MULTICAST_ROUTER_ADVERTISEMENT:
    case icmp::Icmp6Types::MULTICAST_ROUTER_SOLICITATION:
    case icmp::Icmp6Types::MULTICAST_ROUTER_TERMINATION:
    case icmp::Icmp6Types::FMIPV6:
    case icmp::Icmp6Types::RPL_CONTROL:
    case icmp::Icmp6Types::ILNPV6_LOCATOR_UPDATE:
    case icmp::Icmp6Types::DUPLICATE_ADDRESS_REQUEST:
    case icmp::Icmp6Types::DUPLICATE_ADDRESS_CONFIRMATION:
    case icmp::Icmp6Types::MPL_CONTROL:
        break;

    default:
        codec_event(codec, DECODE_ICMP6_TYPE_OTHER);
        break;
    }

    codec.lyr_len = len;
    codec.proto_bits |= PROTO_BIT__ICMP;
    snort.icmph = reinterpret_cast<const icmp::ICMPHdr*>(icmp6h);
    snort.set_pkt_type(PktType::ICMP);
    return true;
}

/******************************************************************
 *************************  L O G G E R   *************************
 ******************************************************************/

void Icmp6Codec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
{
    const icmp::Icmp6Hdr* const icmph = reinterpret_cast<const icmp::Icmp6Hdr*>(raw_pkt);
    TextLog_Print(text_log, "sType:%d  Code:%d  ", icmph->type, static_cast<uint8_t>(icmph->code));
}

/******************************************************************
 ************************* E N C O D E R  *************************
 ******************************************************************/

namespace
{
struct IcmpHdr
{
    // cppcheck-suppress unusedStructMember
    uint8_t type;
    // cppcheck-suppress unusedStructMember
    uint8_t code;
    uint16_t cksum;
    // cppcheck-suppress unusedStructMember
    uint32_t unused;
};
} // namespace

void Icmp6Codec::update(const ip::IpApi& api, const EncodeFlags flags,
    uint8_t* raw_pkt, uint16_t lyr_len, uint32_t& updated_len)
{
    IcmpHdr* h = reinterpret_cast<IcmpHdr*>(raw_pkt);
    updated_len += lyr_len;

    if ( !(flags & UPD_COOKED) || (flags & UPD_REBUILT_FRAG) )
    {
        checksum::Pseudoheader6 ps6;
        h->cksum = 0;

        memcpy(ps6.hdr.sip, api.get_src()->get_ip6_ptr(), sizeof(ps6.hdr.sip));
        memcpy(ps6.hdr.dip, api.get_dst()->get_ip6_ptr(), sizeof(ps6.hdr.dip));
        ps6.hdr.zero = 0;
        ps6.hdr.protocol = IpProtocol::ICMPV6;
        ps6.hdr.len = htons((uint16_t)updated_len);
        h->cksum = checksum::icmp_cksum((uint16_t*)h, updated_len, ps6);
    }
}

void Icmp6Codec::format(bool /*reverse*/, uint8_t* raw_pkt, DecodeData& snort)
{
    snort.icmph = reinterpret_cast<ICMPHdr*>(raw_pkt);
    snort.set_pkt_type(PktType::ICMP);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new Icmp6Module; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new Icmp6Codec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi ipv6_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_ICMP6_NAME,
        CD_ICMP6_HELP,
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

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* cd_icmp6[] =
#endif
{
    &ipv6_api.base,
    nullptr
};

