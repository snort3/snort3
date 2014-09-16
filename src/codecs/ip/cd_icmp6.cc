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
// cd_icmp6.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "snort.h"
#include "framework/codec.h"
#include "protocols/icmp6.h"
#include "protocols/icmp4.h"
#include "codecs/decode_module.h"
#include "codecs/sf_protocols.h"
#include "codecs/decode_module.h"
#include "codecs/codec_events.h"
#include "codecs/ip/checksum.h"
#include "codecs/ip/ip_util.h"
#include "packet_io/active.h"
#include "log/text_log.h"
#include "main/snort_debug.h"

#define CD_ICMP6_NAME "icmp6"
#define CD_ICMP6_HELP "support for internet control message protocol v6"

namespace
{

static const RuleMap icmp6_rules[] =
{
    { DECODE_ICMP6_HDR_TRUNC, "(" CD_ICMP6_NAME ") truncated ICMP6 header" },
    { DECODE_ICMP6_TYPE_OTHER, "(" CD_ICMP6_NAME ") ICMP6 type not decoded" },
    { DECODE_ICMP6_DST_MULTICAST, "(" CD_ICMP6_NAME ") ICMP6 packet to multicast address" },
    { DECODE_ICMPV6_TOO_BIG_BAD_MTU, "(" CD_ICMP6_NAME ") ICMPv6 packet of type 2 (message too big) with MTU field < 1280" },
    { DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE, "(" CD_ICMP6_NAME ") ICMPv6 packet of type 1 (destination unreachable) with non-RFC 2463 code" },
    { DECODE_ICMPV6_SOLICITATION_BAD_CODE, "(" CD_ICMP6_NAME ") ICMPv6 router solicitation packet with a code not equal to 0" },
    { DECODE_ICMPV6_ADVERT_BAD_CODE, "(" CD_ICMP6_NAME ") ICMPv6 router advertisement packet with a code not equal to 0" },
    { DECODE_ICMPV6_SOLICITATION_BAD_RESERVED, "(" CD_ICMP6_NAME ") ICMPv6 router solicitation packet with the reserved field not equal to 0" },
    { DECODE_ICMPV6_ADVERT_BAD_REACHABLE, "(" CD_ICMP6_NAME ") ICMPv6 router advertisement packet with the reachable time field set > 1 hour" },
    { DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE, "(" CD_ICMP6_NAME ") ICMPv6 packet of type 1 (destination unreachable) with non-RFC 4443 code" },
    { DECODE_ICMPV6_NODE_INFO_BAD_CODE, "(" CD_ICMP6_NAME ") ICMPv6 node info query/response packet with a code greater than 2" },
    { 0, nullptr }
};

class Icmp6Module : public DecodeModule
{
public:
    Icmp6Module() : DecodeModule(CD_ICMP6_NAME, CD_ICMP6_HELP) {}

    const RuleMap* get_rules() const
    { return icmp6_rules; }
};


class Icmp6Codec : public Codec
{
public:
    Icmp6Codec() : Codec(CD_ICMP6_NAME){};
    ~Icmp6Codec(){};


    virtual PROTO_ID get_proto_id() { return PROTO_ICMP6; };
    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const RawData&, CodecData&, SnortData&);
    virtual bool encode(EncState*, Buffer* out, const uint8_t* raw_in);
    virtual bool update(Packet*, Layer*, uint32_t* len);
    virtual void log(TextLog* const, const uint8_t* /*raw_pkt*/,
        const Packet* const);
};



} // anonymous namespace


void Icmp6Codec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ICMPV6);
}

//--------------------------------------------------------------------
// decode.c::ICMP6
//--------------------------------------------------------------------

bool Icmp6Codec::decode(const RawData& raw, CodecData& codec, SnortData& snort)
{
    if(raw.len < icmp::ICMP6_HEADER_MIN_LEN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
            "WARNING: Truncated ICMP6 header (%d bytes).\n", raw.len););

        codec_events::decoder_event(DECODE_ICMP6_HDR_TRUNC);
        return false;
    }

    const icmp::ICMP6Hdr* const icmp6h = reinterpret_cast<const icmp::ICMP6Hdr*>(raw.data);


    /* Do checksums */
    if (ScIcmpChecksums())
    {
        uint16_t csum;

        if(snort.ip_api.is_ip4())
        {
            csum = checksum::cksum_add((uint16_t *)(icmp6h), raw.len);
        }
        /* IPv6 traffic */
        else
        {
            checksum::Pseudoheader6 ph6;
            COPY4(ph6.sip, snort.ip_api.get_src()->ip32);
            COPY4(ph6.dip, snort.ip_api.get_dst()->ip32);
            ph6.zero = 0;
            ph6.protocol = snort.ip_api.proto();
            ph6.len = htons((u_short)raw.len);

            csum = checksum::icmp_cksum((uint16_t *)(icmp6h), raw.len, &ph6);
        }
        if(csum)
        {
            snort.decode_flags |= DECODE_ERR_CKSUM_ICMP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE,"ICMP Checksum: BAD\n"););

            if( ScInlineMode() && ScIcmpChecksumDrops() )
                Active_DropPacket();
        }
    }

    const uint16_t dsize = raw.len - icmp::ICMP6_HEADER_MIN_LEN;
    uint16_t len;

    switch(icmp6h->type)
    {
        case icmp::Icmp6Types::ECHO_6:
        case icmp::Icmp6Types::REPLY_6:
            if (dsize >= sizeof(ICMPHdr::icmp_hun.idseq))
            {
                len = icmp::ICMP6_HEADER_NORMAL_LEN;

                if ( snort.ip_api.get_ip6h()->is_dst_multicast() )
                    codec_events::decoder_event(DECODE_ICMP6_DST_MULTICAST);
            }
            else
            {
                codec_events::decoder_event(DECODE_ICMP_DGRAM_LT_ICMPHDR);
                return false;
            }
            break;

        case icmp::Icmp6Types::BIG:
            if (dsize >= sizeof(icmp::ICMP6TooBig))
            {
                icmp::ICMP6TooBig *too_big = (icmp::ICMP6TooBig *)raw.data;

                if (ntohl(too_big->mtu) < 1280)
                    codec_events::decoder_event(DECODE_ICMPV6_TOO_BIG_BAD_MTU);

                len = icmp::ICMP6_HEADER_NORMAL_LEN;
                codec.next_prot_id = IP_EMBEDDED_IN_ICMP6;
            }
            else
            {
                codec_events::decoder_event(DECODE_ICMP_DGRAM_LT_ICMPHDR);
                return false;
            }
            break;

        case icmp::Icmp6Types::TIME:
        case icmp::Icmp6Types::PARAMS:
        case icmp::Icmp6Types::UNREACH:
            if (dsize >= 4)
            {
                if (icmp6h->type == icmp::Icmp6Types::UNREACH)
                {
                    if (icmp6h->code == 2)
                        codec_events::decoder_event(DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE);

                    else if (icmp6h->code > 6)
                        codec_events::decoder_event(DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE);
                }
                len = icmp::ICMP6_HEADER_NORMAL_LEN;
                codec.next_prot_id = IP_EMBEDDED_IN_ICMP6;
            }
            else
            {
                codec_events::decoder_event(DECODE_ICMP_DGRAM_LT_ICMPHDR);
                return false;
            }
            break;

        case icmp::Icmp6Types::ADVERTISEMENT:
            if (dsize >= (sizeof(icmp::ICMP6RouterAdvertisement) - icmp::ICMP6_HEADER_MIN_LEN))
            {
                icmp::ICMP6RouterAdvertisement *ra = (icmp::ICMP6RouterAdvertisement *)raw.data;

                if (icmp6h->code != 0)
                    codec_events::decoder_event(DECODE_ICMPV6_ADVERT_BAD_CODE);

                if (ntohl(ra->reachable_time) > 3600000)
                    codec_events::decoder_event(DECODE_ICMPV6_ADVERT_BAD_REACHABLE);

                len = icmp::ICMP6_HEADER_MIN_LEN;
            }
            else
            {
                codec_events::decoder_event(DECODE_ICMP_DGRAM_LT_ICMPHDR);
                return false;
            }
            break;

        case icmp::Icmp6Types::SOLICITATION:
            if (dsize >= (sizeof(icmp::ICMP6RouterSolicitation) - icmp::ICMP6_HEADER_MIN_LEN))
            {
                icmp::ICMP6RouterSolicitation *rs = (icmp::ICMP6RouterSolicitation *)raw.data;
                if (rs->code != 0)
                    codec_events::decoder_event(DECODE_ICMPV6_SOLICITATION_BAD_CODE);

                if (ntohl(rs->reserved) != 0)
                    codec_events::decoder_event(DECODE_ICMPV6_SOLICITATION_BAD_RESERVED);

                len = icmp::ICMP6_HEADER_MIN_LEN;
            }
            else
            {
                codec_events::decoder_event(DECODE_ICMP_DGRAM_LT_ICMPHDR);
                return false;
            }
            break;

        case icmp::Icmp6Types::NODE_INFO_QUERY:
        case icmp::Icmp6Types::NODE_INFO_RESPONSE:
            if (dsize >= (sizeof(icmp::ICMP6NodeInfo) - icmp::ICMP6_HEADER_MIN_LEN))
            {
                icmp::ICMP6NodeInfo *ni = (icmp::ICMP6NodeInfo *)raw.data;
                if (ni->code > 2)
                    codec_events::decoder_event(DECODE_ICMPV6_NODE_INFO_BAD_CODE);

                /* TODO: Add alert for INFO Response, code == 1 || code == 2)
                 * and there is data.
                 */
                 len = icmp::ICMP6_HEADER_MIN_LEN;
            }
            else
            {
                codec_events::decoder_event(DECODE_ICMP_DGRAM_LT_ICMPHDR);
                return false;
            }
            break;

        default:
            codec_events::decoder_event(DECODE_ICMP6_TYPE_OTHER);
            len = icmp::ICMP6_HEADER_MIN_LEN;
            break;
    }

    codec.lyr_len = len;
    codec.proto_bits |= PROTO_BIT__ICMP;
    snort.icmph = reinterpret_cast<const icmp::ICMPHdr*>(icmp6h);
    snort.packet_type = PKT_TYPE__ICMP6;
    return true;
}


/******************************************************************
 *************************  L O G G E R   *************************
 ******************************************************************/

void Icmp6Codec::log(TextLog* const text_log, const uint8_t* raw_pkt,
                const Packet* const)
{
    const icmp::ICMP6Hdr* const icmph = reinterpret_cast<const icmp::ICMP6Hdr*>(raw_pkt);
    TextLog_Print(text_log, "sType:%d  Code:%d  ", icmph->type, icmph->code);
}

/******************************************************************
 ************************* E N C O D E R  *************************
 ******************************************************************/


namespace
{

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint32_t unused;
} IcmpHdr;

} // namespace


bool Icmp6Codec::encode(EncState* enc, Buffer* out, const uint8_t* /*raw_in*/)
{
    checksum::Pseudoheader6 ps6;
    IcmpHdr* ho;

    // ip + udp headers are copied separately because there
    // may be intervening extension headers which aren't copied


#if 0
    // Now performed in cd_prot_embedded_in_icmp.cc

    // copy first 8 octets of original ip data (ie udp header)
    // TBD: copy up to minimum MTU worth of data
    if (!update_buffer(out, icmp::ICMP_UNREACH_DATA_LEN))
        return false;
    memcpy(out->base, raw_in, icmp::ICMP_UNREACH_DATA_LEN);
    // copy original ip header
    if (!update_buffer(out, enc->ip_len))
        return false;

    // Now performed in cd_ip6_embedded_in_icmp.cc
    // TBD should be able to elminate enc->ip_hdr by using layer-2
    memcpy(out->base, enc->ip_hdr, enc->ip_len);
    ((ip::IP6Hdr*)out->base)->ip6_next = IPPROTO_UDP;

#endif


    if (!update_buffer(out, sizeof(*ho)))
        return false;

    ho = reinterpret_cast<IcmpHdr*>(out->base);
    ho->type = static_cast<uint8_t>(icmp::Icmp6Types::UNREACH);
    ho->code = static_cast<uint8_t>(ip_util::get_icmp6_code(enc->type));   // port unreachable
    ho->cksum = 0;
    ho->unused = 0;

    enc->proto = IPPROTO_ICMPV6;
    int len = buff_diff(out, (uint8_t *)ho);

    const ip::IP6Hdr* const ip6h = enc->p->ptrs.ip_api.get_ip6h();

    memcpy(ps6.sip, ip6h->ip6_src.u6_addr8, sizeof(ps6.sip));
    memcpy(ps6.dip, ip6h->ip6_dst.u6_addr8, sizeof(ps6.dip));
    ps6.zero = 0;
    ps6.protocol = IPPROTO_ICMPV6;
    ps6.len = htons((uint16_t)(len));

    ho->cksum = checksum::icmp_cksum((uint16_t *)ho, len, &ps6);

    return true;
}

bool Icmp6Codec::update (Packet* p, Layer* lyr, uint32_t* len)
{
    IcmpHdr* h = (IcmpHdr*)(lyr->start);

    *len += sizeof(*h) + p->dsize;

    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) ) {
        checksum::Pseudoheader6 ps6;
        h->cksum = 0;

        memcpy(ps6.sip, &p->ptrs.ip_api.get_src()->ip32, sizeof(ps6.sip));
        memcpy(ps6.dip, &p->ptrs.ip_api.get_dst()->ip32, sizeof(ps6.dip));
        ps6.zero = 0;
        ps6.protocol = IPPROTO_ICMPV6;
        ps6.len = htons((uint16_t)*len);
        h->cksum = checksum::icmp_cksum((uint16_t *)h, *len, &ps6);
    }

    return true;
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

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi ipv6_api =
{
    {
        PT_CODEC,
        CD_ICMP6_NAME,
        CD_ICMP6_HELP,
        CDAPI_PLUGIN_V0,
        0,
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
{
    &ipv6_api.base,
    nullptr
};
#else
const BaseApi* cd_icmp6 = &ipv6_api.base;
#endif
