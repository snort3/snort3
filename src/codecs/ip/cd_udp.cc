/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
// cd_udp.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <string.h>

#include "utils/dnet_header.h"
#include "codecs/codec_module.h"
#include "protocols/udp.h"
#include "protocols/teredo.h"
#include "protocols/protocol_ids.h"
#include "protocols/icmp4.h"
#include "protocols/ipv4.h"
#include "protocols/protocol_ids.h"
#include "codecs/ip/checksum.h"
#include "log/text_log.h"

#include "framework/codec.h"
#include "packet_io/active.h"
#include "codecs/codec_events.h"
#include "snort_config.h"
#include "parser/config_file.h"
#include "codecs/ip/ip_util.h"
#include "main/snort_debug.h"

#define CD_UDP_NAME "udp"
#define CD_UDP_HELP "support for user datagram protocol"

namespace
{

const PegInfo pegs[]
{
    { "bad checksum (ip4)", "nonzero udp over ipv4 checksums" },
    { "bad checksum (ip6)", "nonzero udp over ipv6 checksums" },
    { nullptr, nullptr }
};

struct Stats
{
    PegCount bad_ip4_cksum;
    PegCount bad_ip6_cksum;
};

static THREAD_LOCAL Stats stats;

static const Parameter udp_params[] =
{
    { "deep_teredo_inspection", Parameter::PT_BOOL, nullptr, "false",
      "look for Teredo on all UDP ports (default is only 3544)" },

    { "enable_gtp", Parameter::PT_BOOL, nullptr, "false",
      "decode GTP encapsulations" },

    { "gtp_ports", Parameter::PT_BIT_LIST, "65535",
      "2152 3386", "set GTP ports" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


static const RuleMap udp_rules[] =
{

    { DECODE_UDP_DGRAM_LT_UDPHDR, "truncated UDP header" },
    { DECODE_UDP_DGRAM_INVALID_LENGTH, "invalid UDP header, length field < 8" },
    { DECODE_UDP_DGRAM_SHORT_PACKET, "short UDP packet, length field > payload length" },
    { DECODE_UDP_DGRAM_LONG_PACKET, "long UDP packet, length field < payload length" },
    { DECODE_UDP_IPV6_ZERO_CHECKSUM, "invalid IPv6 UDP packet, checksum zero" },
    { DECODE_UDP_LARGE_PACKET, "misc large UDP Packet" },
    { DECODE_UDP_PORT_ZERO, "BAD-TRAFFIC UDP port 0 traffic" },
    { 0, nullptr }
};

constexpr uint16_t GTP_U_PORT = 2152;
constexpr uint16_t GTP_U_PORT_V0 = 3386;

class UdpModule : public CodecModule
{
public:
    UdpModule() : CodecModule(CD_UDP_NAME, CD_UDP_HELP, udp_params) {}

    const RuleMap* get_rules() const override
    { return udp_rules; }

    const PegInfo* get_pegs() const override
    { return pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&stats; }

    bool set(const char*, Value& v, SnortConfig* sc) override
    {
        if ( v.is("deep_teredo_inspection") )
        {
            sc->enable_teredo = v.get_long();  // FIXIT-L move to existing bitfield
        }
        else if ( v.is("gtp_ports") )
        {
            if ( sc->gtp_ports == nullptr )
                sc->gtp_ports = new PortList;

//            sc->gtp_ports->reset(); // called in v.get_bits();
            v.get_bits(*(sc->gtp_ports));
        }
        else if ( v.is("enable_gtp") )
        {
            if ( v.get_bool() )
            {
                if ( sc->gtp_ports == nullptr )
                {
                    sc->gtp_ports = new PortList;
                    sc->gtp_ports->reset();
                    sc->gtp_ports->set(GTP_U_PORT);
                    sc->gtp_ports->set(GTP_U_PORT_V0);
                }
            }
        }
        else
        {
            return false;
        }

        return true;
    }
};


class UdpCodec : public Codec
{
public:
    UdpCodec() : Codec(CD_UDP_NAME){};
    ~UdpCodec(){};


    void get_protocol_ids(std::vector<uint16_t>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;

    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
                        EncState&, Buffer&) override;
    bool update(Packet*, Layer*, uint32_t* len) override;
    void format(EncodeFlags, const Packet* p, Packet* c, Layer*) override;
    void log(TextLog* const, const uint8_t* /*raw_pkt*/,
        const Packet* const) override;
    
};

} // anonymous namespace





static inline void UDPMiscTests(const DecodeData&,
                                const CodecData&,
                                uint32_t pay_len);




void UdpCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_ID_UDP);
}


bool UdpCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    uint16_t uhlen;
    bool fragmented_udp_flag = false;

    if(raw.len < udp::UDP_HEADER_LEN)
    {
        codec_events::decoder_event(codec, DECODE_UDP_DGRAM_LT_UDPHDR);
        return false;
    }

    /* set the ptr to the start of the UDP header */
    const udp::UDPHdr* const udph =
        reinterpret_cast<const udp::UDPHdr*>(raw.data);

    // FIXIT-M since we no longer let UDP fragments through, erase extra code
    if ((snort.decode_flags & DECODE_FRAG) == 0)
    {
        uhlen = ntohs(udph->uh_len);
    }
    else if(snort.ip_api.is_ip6())
    {
        const uint16_t ip_len = snort.ip_api.get_ip6h()->len();
        /* subtract the distance from udp header to 1st ip6 extension */
        /* This gives the length of the UDP "payload", when fragmented */
        uhlen = ip_len - ((uint8_t *)udph - snort.ip_api.ip_data());
        fragmented_udp_flag = true;
    }
    else
    {
        const ip::IP4Hdr* const ip4h = snort.ip_api.get_ip4h();
        uhlen = ip4h->len() - ip4h->hlen();
        fragmented_udp_flag = true;
    }

    /* verify that the header raw.len is a valid value */
    if(uhlen < udp::UDP_HEADER_LEN)
    {
        codec_events::decoder_event(codec, DECODE_UDP_DGRAM_INVALID_LENGTH);
        return false;
    }

    /* make sure there are enough bytes as designated by length field */
    if(uhlen > raw.len)
    {
        codec_events::decoder_event(codec, DECODE_UDP_DGRAM_SHORT_PACKET);
        return false;
    }
    else if(uhlen < raw.len)
    {
        codec_events::decoder_event(codec, DECODE_UDP_DGRAM_LONG_PACKET);
        return false;
    }

    if (ScUdpChecksums())
    {
        /* look at the UDP checksum to make sure we've got a good packet */
        uint16_t csum;
        PegCount* bad_cksum_cnt;

        if(snort.ip_api.is_ip4())
        {
            bad_cksum_cnt = &(stats.bad_ip4_cksum);

            /* Don't do checksum calculation if
             * 1) Fragmented, OR
             * 2) UDP header chksum value is 0.
             */
            if( !fragmented_udp_flag && udph->uh_chk )
            {
                checksum::Pseudoheader ph;
                const ip::IP4Hdr* const ip4h = snort.ip_api.get_ip4h();
                ph.sip = ip4h->get_src();
                ph.dip = ip4h->get_dst();
                ph.zero = 0;
                ph.protocol = ip4h->proto();
                ph.len = udph->uh_len;
                
                csum = checksum::udp_cksum((uint16_t *)(udph), uhlen, &ph);
            }
            else
            {
                csum = 0;
            }
        }
        else
        {
            bad_cksum_cnt = &(stats.bad_ip6_cksum);

            /* Alert on checksum value 0 for ipv6 packets */
            if(!udph->uh_chk)
            {
                csum = 1;
                codec_events::decoder_event(codec, DECODE_UDP_IPV6_ZERO_CHECKSUM);
            }
            /* Don't do checksum calculation if
             * 1) Fragmented
             * (UDP checksum is not optional in IP6)
             */
            else if( !fragmented_udp_flag )
            {
                checksum::Pseudoheader6 ph6;
                const ip::IP6Hdr* const ip6h = snort.ip_api.get_ip6h();
                COPY4(ph6.sip, ip6h->ip6_src.u6_addr32);
                COPY4(ph6.dip, ip6h->ip6_dst.u6_addr32);
                ph6.zero = 0;
                ph6.protocol = codec.ip6_csum_proto;
                ph6.len = htons((u_short)raw.len);

                csum = checksum::udp_cksum((uint16_t *)(udph), uhlen, &ph6);
            }
            else
            {
                csum = 0;
            }
        }
        if(csum && !codec.is_cooked())
        {
            if ( !(codec.codec_flags & CODEC_UNSURE_ENCAP) )
            {
                (*bad_cksum_cnt)++;
                snort.decode_flags |= DECODE_ERR_CKSUM_UDP;
            }
            return false;
        }
    }
    const uint16_t src_port = udph->src_port();
    const uint16_t dst_port =  udph->dst_port();

    /* fill in the printout data structs */
    snort.udph = udph;
    snort.sp = src_port;
    snort.dp = dst_port;
    codec.lyr_len = udp::UDP_HEADER_LEN;
    codec.proto_bits |= PROTO_BIT__UDP;
    snort.set_pkt_type(PktType::UDP);

    // set in packet manager
    UDPMiscTests(snort, codec, uhlen - udp::UDP_HEADER_LEN);

    if (ScGTPDecoding() &&
         (ScIsGTPPort(src_port)||ScIsGTPPort(dst_port)))
    {
        if ( !(snort.decode_flags & DECODE_FRAG) )
            codec.next_prot_id = PROTOCOL_GTP;
    }
    else if (teredo::is_teredo_port(src_port) ||
        teredo::is_teredo_port(dst_port) ||
        ScDeepTeredoInspection())
    {
        codec.next_prot_id = PROTOCOL_TEREDO;
    }

    
    return true;
}


/* UDP-layer decoder alerts */
static inline void UDPMiscTests(const DecodeData& snort,
                                const CodecData& codec,
                                uint32_t pay_len)
{
    if (pay_len > 4000)
        codec_events::decoder_event(codec, DECODE_UDP_LARGE_PACKET);

    if (snort.sp == 0 || snort.dp == 0)
        codec_events::decoder_event(codec, DECODE_UDP_PORT_ZERO);
}

void UdpCodec::log(TextLog* const text_log, const uint8_t* raw_pkt, const Packet* const)
{
    const udp::UDPHdr* udph = reinterpret_cast<const udp::UDPHdr*>(raw_pkt);

    TextLog_Print(text_log, "SrcPort:%d DstPort:%d Len:%d",
            ntohs(udph->uh_sport), ntohs(udph->uh_dport),
            ntohs(udph->uh_len) - udp::UDP_HEADER_LEN);
}

/******************************************************************
 ******************** E N C O D E R  ******************************
 ******************************************************************/


bool UdpCodec::encode(const uint8_t* const raw_in, const uint16_t /*raw_len*/,
                        EncState& enc, Buffer& buf)
{   
    // If we enter this function, this packe is some sort of tunnel.

    if(!buf.allocate(udp::UDP_HEADER_LEN))
        return false;

    const udp::UDPHdr* const hi = reinterpret_cast<const udp::UDPHdr*>(raw_in);
    udp::UDPHdr* const udph_out = reinterpret_cast<udp::UDPHdr*>(buf.data());

    if ( forward(enc.flags) )
    {
        udph_out->uh_sport = hi->uh_sport;
        udph_out->uh_dport = hi->uh_dport;
    }
    else
    {
        udph_out->uh_sport = hi->uh_dport;
        udph_out->uh_dport = hi->uh_sport;
    }

    const uint16_t len = (uint16_t)buf.size();
    udph_out->uh_len = htons((uint16_t)len);
    udph_out->uh_chk = 0;

    const ip::IpApi& ip_api = enc.ip_api;
    if (ip_api.is_ip4())
    {
        checksum::Pseudoheader ps;
        const IP4Hdr* const ip4h = ip_api.get_ip4h();
        ps.sip = ip4h->get_src();
        ps.dip = ip4h->get_dst();
        ps.zero = 0;
        ps.protocol = IPPROTO_ID_UDP;
        ps.len = udph_out->uh_len;
        udph_out->uh_chk = checksum::udp_cksum((uint16_t *)udph_out, len, &ps);
    }
    else
    {
        checksum::Pseudoheader6 ps6;
        const ip::IP6Hdr* const ip6h = ip_api.get_ip6h();
        memcpy(ps6.sip, ip6h->get_src()->u6_addr8, sizeof(ps6.sip));
        memcpy(ps6.dip, ip6h->get_dst()->u6_addr8, sizeof(ps6.dip));
        ps6.zero = 0;
        ps6.protocol = IPPROTO_ID_UDP;
        ps6.len = udph_out->uh_len;
        udph_out->uh_chk = checksum::udp_cksum((uint16_t*)udph_out, len, &ps6);
    }

    enc.next_proto = IPPROTO_ID_UDP;
    enc.next_ethertype = 0;
    return true;
}

bool UdpCodec::update(Packet* p, Layer* lyr, uint32_t* len)
{
    udp::UDPHdr* h = (udp::UDPHdr*)(lyr->start);

    *len += sizeof(*h);
    h->uh_len = htons((uint16_t)*len);


    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) )
    {
        const ip::IpApi& ip_api = p->ptrs.ip_api;
        h->uh_chk = 0;

        if (ip_api.is_ip4()) {
            checksum::Pseudoheader ps;
            const ip::IP4Hdr* const ip4h = ip_api.get_ip4h();
            ps.sip = ip4h->get_src();
            ps.dip = ip4h->get_dst();
            ps.zero = 0;
            ps.protocol = IPPROTO_ID_UDP;
            ps.len = htons((uint16_t)*len);
            h->uh_chk = checksum::udp_cksum((uint16_t *)h, *len, &ps);
        }
        else
        {
            checksum::Pseudoheader6 ps6;
            const ip::IP6Hdr* const ip6h = ip_api.get_ip6h();
            memcpy(ps6.sip, &ip6h->ip6_src.u6_addr32, sizeof(ps6.sip));
            memcpy(ps6.dip, &ip6h->ip6_dst.u6_addr32, sizeof(ps6.dip));
            ps6.zero = 0;
            ps6.protocol = IPPROTO_ID_UDP;
            ps6.len = htons((uint16_t)*len);
            h->uh_chk = checksum::udp_cksum((uint16_t *)h, *len, &ps6);
        }
    }

    return true;
}

void UdpCodec::format (EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    udp::UDPHdr* ch = (udp::UDPHdr*)lyr->start;
    c->ptrs.udph = ch;

    if ( reverse(f) )
    {
        int i = (int)(lyr - c->layers);
        udp::UDPHdr* ph = (udp::UDPHdr*)p->layers[i].start;

        ch->uh_sport = ph->uh_dport;
        ch->uh_dport = ph->uh_sport;
    }
    c->ptrs.sp = ntohs(ch->uh_sport);
    c->ptrs.dp = ntohs(ch->uh_dport);
    c->ptrs.set_pkt_type(PktType::UDP);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------


static Module* mod_ctor()
{ return new UdpModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new UdpCodec(); }

static void dtor(Codec *cd)
{ delete cd; }


static const CodecApi udp_api =
{
    {
        PT_CODEC,
        CD_UDP_NAME,
        CD_UDP_HELP,
        CDAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
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
    &udp_api.base,
    nullptr
};
#else
const BaseApi* cd_udp = &udp_api.base;
#endif
