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
#include "protocols/tcp.h"
#include "codecs/codec_events.h"
#include "log/text_log.h"
#include "main/snort.h"
#include "log/messages.h"
#include "protocols/packet_manager.h"
#include "protocols/icmp4.h"
#include "protocols/udp.h"

namespace
{

#define ICMP4_IP_NAME "icmp4_ip"
#define ICMP4_IP_HELP "support for IP in ICMPv4"

class Icmp4IpCodec : public Codec
{
public:
    Icmp4IpCodec() : Codec(ICMP4_IP_NAME){};
    ~Icmp4IpCodec() {};


    virtual void get_protocol_ids(std::vector<uint16_t>&);
    virtual bool decode(const RawData&, CodecData&, DecodeData&);
    virtual void log(TextLog* const, const uint8_t* /*raw_pkt*/,
                    const Packet* const);
};

} // namespace


void Icmp4IpCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IP_EMBEDDED_IN_ICMP4);
}

bool Icmp4IpCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    uint32_t ip_len;       /* length from the start of the ip hdr to the
                             * pkt end */

    /* do a little validation */
    if(raw.len < ip::IP4_HEADER_LEN)
    {
        codec_events::decoder_event(codec, DECODE_ICMP_ORIG_IP_TRUNCATED);
        return false;
    }

    /* lay the IP struct over the raw data */
    const IP4Hdr *ip4h = reinterpret_cast<const IP4Hdr *>(raw.data);

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if((ip4h->get_ver() != 4) && !snort.ip_api.is_ip6())
    {
        codec_events::decoder_event(codec, DECODE_ICMP_ORIG_IP_VER_MISMATCH);
        return false;
    }

    const uint32_t hlen = ip4h->get_hlen() << 2;    /* set the IP header length */

    if(raw.len < hlen)
    {
        codec_events::decoder_event(codec, DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP);
        return false;
    }

    /* set the remaining packet length */
    ip_len = raw.len - hlen;

    uint16_t orig_frag_offset = ntohs(ip4h->get_off());
    orig_frag_offset &= 0x1FFF;

    if (orig_frag_offset == 0)
    {
        /* Original IP payload should be 64 bits */
        if (ip_len < 8)
        {
            codec_events::decoder_event(codec, DECODE_ICMP_ORIG_PAYLOAD_LT_64);

            return false;
        }
        /* ICMP error packets could contain as much of original payload
         * as possible, but not exceed 576 bytes
         */
        else if (ntohs(snort.ip_api.len()) > 576)
        {
            codec_events::decoder_event(codec, DECODE_ICMP_ORIG_PAYLOAD_GT_576);
        }
    }
    else
    {
        /* RFC states that only first frag will get an ICMP response */
        codec_events::decoder_event(codec, DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET);
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
            codec.proto_bits |= PROTO_BIT__TCP_EMBED_ICMP;
            break;

        case IPPROTO_UDP:
            codec.proto_bits |= PROTO_BIT__UDP_EMBED_ICMP;
            break;

        case IPPROTO_ICMP:
            codec.proto_bits |= PROTO_BIT__ICMP_EMBED_ICMP;
            break;
    }

    // If you change this, change the buffer and
    // memcpy length in encode() below !!
    codec.lyr_len = ip::IP4_HEADER_LEN;
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
                    const Packet* const)
{
    const IP4Hdr* const ip4h = reinterpret_cast<const IP4Hdr*>(raw_pkt);
    TextLog_Puts(text_log, "\n\t**** ORIGINAL DATAGRAM DUMP: ****");
    TextLog_NewLine(text_log);
    TextLog_Puts(text_log, "\tIPv4\n\t\t");

    // COPIED DIRECTLY FROM ipv4 CODEC.  This is specificially replicated since
    //      the two are not necessarily the same.

    // FIXIT-H  -->  This does NOT obfuscate correctly
    if (ScObfuscate())
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

    const uint16_t hlen = ip4h->get_hlen() << 2;
    const uint16_t len = ntohs(ip4h->get_len());
    const uint16_t frag_off = ntohs(ip4h->get_off());

    TextLog_Print(text_log, "Next:%s(%02X) TTL:%u TOS:0x%X ID:%u IpLen:%u DgmLen:%u",
            PacketManager::get_proto_name(ip4h->get_proto()),
            ip4h->get_proto(), ip4h->get_ttl(), ip4h->get_tos(),
            ip4h->get_id(), hlen, len);


    /* print the reserved bit if it's set */
    if(frag_off & 0x8000)
        TextLog_Puts(text_log, " RB");

    /* printf more frags/don't frag bits */
    if(frag_off & 0x4000)
        TextLog_Puts(text_log, " DF");

    bool mf = false;
    if(frag_off & 0x2000)
    {
        mf = true;
        TextLog_Puts(text_log, " MF");
    }


#if 0
    // FIXIT-L - J  more ip options fixits
    /* print IP options */
    if(p->ip_option_count > 0)
    {
        LogIpOptions(text_log, p);
    }
#endif

    if( mf && (frag_off & 0x1FFF) && ((len - hlen > 0)))
    {
        TextLog_NewLine(text_log);
        TextLog_Puts(text_log, "\t\t");
        TextLog_Print(text_log, "Frag Offset: 0x%04X   Frag Size: 0x%04X",
                (frag_off & 0x1FFF), (len - hlen));
    }

    TextLog_NewLine(text_log);
    TextLog_Putc(text_log, '\t');


    /*  EMBEDDED PROTOCOL */
    switch(ip4h->get_proto())
    {
        case IPPROTO_TCP: /* decode the interesting part of the header */
        {
            const tcp::TCPHdr* tcph = reinterpret_cast<const tcp::TCPHdr*>
                (raw_pkt + hlen);
            TextLog_Puts(text_log, "TCP\n\t\t");
            TextLog_Print(text_log, "SrcPort:%u  DstPort:%u  Seq: 0x%lX  "
                    "Ack: 0x%lX  Win: 0x%X  TcpLen: %d",ntohs(tcph->th_sport),
                    ntohs(tcph->th_dport), (u_long) ntohl(tcph->th_seq),
                    (u_long) ntohl(tcph->th_ack),
                    ntohs(tcph->th_win), tcph->off() << 2);

            break;
        }

        case IPPROTO_UDP:
        {
            const udp::UDPHdr* udph = reinterpret_cast<const udp::UDPHdr*>
                (raw_pkt + hlen);
            TextLog_Puts(text_log, "UDP\n\t\t");
            TextLog_Print(text_log, "SourcePort:%d DestPort:%d Len:%d",
                    ntohs(udph->uh_sport), ntohs(udph->uh_dport),
                ntohs(udph->uh_len) - udp::UDP_HEADER_LEN);
            break;
        }

        case IPPROTO_ICMP:
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
        // XXX-IPv6 "NOT YET IMPLEMENTED - ICMP printing"
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
                PacketManager::get_proto_name(ip4h->get_proto()),
                ip4h->get_proto());
            break;
        }
    }
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
        ICMP4_IP_HELP,
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
