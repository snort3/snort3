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
// cd_icmp4_ip.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "protocols/icmp4.h"
#include "protocols/packet_manager.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"

using namespace snort;

namespace
{
#define ICMP4_IP_NAME "icmp4_ip"
#define ICMP4_IP_HELP "support for IP in ICMPv4"

class Icmp4IpCodec : public Codec
{
public:
    Icmp4IpCodec() : Codec(ICMP4_IP_NAME) { }

    void get_protocol_ids(std::vector<ProtocolId>&) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
};
} // namespace

void Icmp4IpCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{ v.push_back(ProtocolId::IP_EMBEDDED_IN_ICMP4); }

bool Icmp4IpCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    if (raw.len < ip::IP4_HEADER_LEN)
    {
        codec_event(codec, DECODE_ICMP_ORIG_IP_TRUNCATED);
        return false;
    }

    /* lay the IP struct over the raw data */
    const ip::IP4Hdr* const ip4h = reinterpret_cast<const ip::IP4Hdr*>(raw.data);

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if ((ip4h->ver() != 4) && !snort.ip_api.is_ip6())
    {
        codec_event(codec, DECODE_ICMP_ORIG_IP_VER_MISMATCH);
        return false;
    }

    const uint16_t hlen = ip4h->hlen();

    if (raw.len < hlen)
    {
        codec_event(codec, DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP);
        return false;
    }

    /* set the remaining packet length */
    if (ip4h->off() == 0)
    {
        const uint32_t ip_len = raw.len - hlen;

        /* Original IP payload should be 64 bits */
        if (ip_len < 8)
        {
            codec_event(codec, DECODE_ICMP_ORIG_PAYLOAD_LT_64);
            return false;
        }
        /* ICMP error packets could contain as much of original payload
         * as possible, but not exceed 576 bytes
         */
        else if (snort.ip_api.dgram_len() > 576)
        {
            codec_event(codec, DECODE_ICMP_ORIG_PAYLOAD_GT_576);
        }
    }
    else
    {
        /* RFC states that only first frag will get an ICMP response */
        codec_event(codec, DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET);
        return false;
    }

    switch (ip4h->proto())
    {
    case IpProtocol::TCP:     /* decode the interesting part of the header */
        codec.proto_bits |= PROTO_BIT__TCP_EMBED_ICMP;
        break;

    case IpProtocol::UDP:
        codec.proto_bits |= PROTO_BIT__UDP_EMBED_ICMP;
        break;

    case IpProtocol::ICMPV4:
        codec.proto_bits |= PROTO_BIT__ICMP_EMBED_ICMP;
        break;
    default:
        codec.proto_bits |= PROTO_BIT__ICMP_EMBED_OTHER;
        break;
    }

    // If you change this, change the buffer and
    // memcpy length in encode() below !!
    codec.lyr_len = hlen;
    return true;
}

struct ip4_addr
{
    union
    {
        uint32_t addr32;
        uint8_t addr8[4];
    };
};

void Icmp4IpCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
{
    const ip::IP4Hdr* const ip4h = reinterpret_cast<const ip::IP4Hdr*>(raw_pkt);
    TextLog_Puts(text_log, "\n\t**** ORIGINAL DATAGRAM DUMP: ****");
    TextLog_NewLine(text_log);
    TextLog_Puts(text_log, "\tIPv4\n\t\t");

    // COPIED DIRECTLY FROM ipv4 CODEC.  This is specifically replicated since
    //      the two are not necessarily the same.

    // FIXIT-H this does NOT obfuscate correctly
    if (SnortConfig::obfuscate())
    {
        TextLog_Print(text_log, "xxx.xxx.xxx.xxx -> xxx.xxx.xxx.xxx");
    }
    else
    {
        ip4_addr src, dst;
        src.addr32 = ip4h->get_src();
        dst.addr32 = ip4h->get_dst();

        TextLog_Print(text_log, "%d.%d.%d.%d -> %d.%d.%d.%d",
            (int)src.addr8[0], (int)src.addr8[1],
            (int)src.addr8[2], (int)src.addr8[3],
            (int)dst.addr8[0], (int)dst.addr8[1],
            (int)dst.addr8[2], (int)dst.addr8[3]);
    }

    TextLog_NewLine(text_log);
    TextLog_Puts(text_log, "\t\t");

    const uint16_t hlen = ip4h->hlen();
    const uint16_t len = ip4h->len();
    const uint16_t frag_off = ip4h->off_w_flags();

    TextLog_Print(text_log, "Next:%s(%02X) TTL:%u TOS:0x%X ID:%u IpLen:%u DgmLen:%u",
        PacketManager::get_proto_name(ip4h->proto()),
        ip4h->proto(), ip4h->ttl(), ip4h->tos(),
        ip4h->id(), hlen, len);

    /* print the reserved bit if it's set */
    if (frag_off & 0x8000)
        TextLog_Puts(text_log, " RB");

    /* printf more frags/don't frag bits */
    if (frag_off & 0x4000)
        TextLog_Puts(text_log, " DF");

    bool mf = false;
    if (frag_off & 0x2000)
    {
        mf = true;
        TextLog_Puts(text_log, " MF");
    }

#if 0
    // FIXIT-L more ip options fixits
    /* print IP options */
    if (p->ip_option_count > 0)
    {
        LogIpOptions(text_log, p);
    }
#endif

    if ( mf && (frag_off & 0x1FFF) && ((len - hlen > 0)))
    {
        TextLog_NewLine(text_log);
        TextLog_Puts(text_log, "\t\t");
        TextLog_Print(text_log, "Frag Offset: 0x%04X   Frag Size: 0x%04X",
            (frag_off & 0x1FFF), (len - hlen));
    }

    TextLog_NewLine(text_log);
    TextLog_Putc(text_log, '\t');

    /*  EMBEDDED PROTOCOL */
    switch (ip4h->proto())
    {
    case IpProtocol::TCP:     /* decode the interesting part of the header */
    {
        const tcp::TCPHdr* tcph = reinterpret_cast<const tcp::TCPHdr*>
            (raw_pkt + hlen);
        TextLog_Puts(text_log, "TCP\n\t\t");
        TextLog_Print(text_log, "SrcPort:%u  DstPort:%u  Seq: 0x%lX  "
            "Ack: 0x%lX  Win: 0x%X  TcpLen: %d",ntohs(tcph->th_sport),
            ntohs(tcph->th_dport), (u_long)ntohl(tcph->th_seq),
            (u_long)ntohl(tcph->th_ack),
            ntohs(tcph->th_win), tcph->off());

        break;
    }

    case IpProtocol::UDP:
    {
        const udp::UDPHdr* udph = reinterpret_cast<const udp::UDPHdr*>
            (raw_pkt + hlen);
        TextLog_Puts(text_log, "UDP\n\t\t");
        TextLog_Print(text_log, "SourcePort:%d DestPort:%d Len:%d",
            ntohs(udph->uh_sport), ntohs(udph->uh_dport),
            ntohs(udph->uh_len) - udp::UDP_HEADER_LEN);
        break;
    }

    case IpProtocol::ICMPV4:
    {
        const icmp::ICMPHdr* icmph = reinterpret_cast<const icmp::ICMPHdr*>
            (raw_pkt + hlen);

        TextLog_Puts(text_log, "ICMPv4\n\t\t");
        TextLog_Print(text_log, "Type:%d  Code:%d  Csum:%u",
            icmph->type, icmph->code, ntohs(icmph->csum));

        switch (icmph->type)
        {
        case icmp::IcmpType::DEST_UNREACH:
        case icmp::IcmpType::TIME_EXCEEDED:
        case icmp::IcmpType::SOURCE_QUENCH:
            break;

        case icmp::IcmpType::PARAMETERPROB:
            if (icmph->code == 0)
                TextLog_Print(text_log, "  Ptr: %u", icmph->s_icmp_pptr);
            break;

        case ICMP_REDIRECT:
            // FIXIT-L -IPv6 "NOT YET IMPLEMENTED - ICMP printing"
            break;

        case icmp::IcmpType::ECHO_4:
        case icmp::IcmpType::ECHOREPLY:
        case icmp::IcmpType::TIMESTAMP:
        case icmp::IcmpType::TIMESTAMPREPLY:
        case icmp::IcmpType::INFO_REQUEST:
        case icmp::IcmpType::INFO_REPLY:
        case icmp::IcmpType::ADDRESS:
        case icmp::IcmpType::ADDRESSREPLY:
            TextLog_Print(text_log, "  Id: %u  SeqNo: %u",
                ntohs(icmph->s_icmp_id), ntohs(icmph->s_icmp_seq));
            break;

        case icmp::IcmpType::ROUTER_ADVERTISE:
            TextLog_Print(text_log, "  Addrs: %u  Size: %u  Lifetime: %u",
                icmph->s_icmp_num_addrs, icmph->s_icmp_wpa,
                ntohs(icmph->s_icmp_lifetime));
            break;

        default:
            break;
        }
        break;
    }
    default:
    {
        TextLog_Print(text_log, "Protocol:%s(%02X)",
            PacketManager::get_proto_name(ip4h->proto()),
            ip4h->proto());
        break;
    }
    }
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new Icmp4IpCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi icmp4_ip_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        ICMP4_IP_NAME,
        ICMP4_IP_HELP,
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
#else
const BaseApi* cd_icmp4_ip[] =
#endif
{
    &icmp4_ip_api.base,
    nullptr
};

