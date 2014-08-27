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

#include <string.h>
#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include "codecs/decode_module.h"
#include "protocols/udp.h"
#include "protocols/teredo.h"
#include "protocols/protocol_ids.h"
#include "protocols/icmp4.h"
#include "protocols/ipv4.h"
#include "protocols/protocol_ids.h"
#include "codecs/ip/checksum.h"

#include "framework/codec.h"
#include "packet_io/active.h"
#include "codecs/codec_events.h"
#include "codecs/sf_protocols.h"
#include "snort_config.h"
#include "parser/config_file.h"
#include "codecs/ip/ip_util.h"


namespace
{


#define CD_UDP_NAME "udp"
static const Parameter udp_params[] =
{
    { "deep_teredo_inspection", Parameter::PT_BOOL, nullptr, "false",
      "look for Teredo on all UDP ports (default is only 3544)" },

    { "enable_gtp", Parameter::PT_BOOL, nullptr, "false",
      "decode GTP encapsulations" },

    // FIXIT-L use PT_BIT_LIST
    { "gtp_ports", Parameter::PT_STRING, nullptr,
      "'2152 3386'", "set GTP ports" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


static const RuleMap udp_rules[] =
{

    { DECODE_UDP_DGRAM_LT_UDPHDR, "(" CD_UDP_NAME ") Truncated UDP Header" },
    { DECODE_UDP_DGRAM_INVALID_LENGTH, "(" CD_UDP_NAME ") Invalid UDP header, length field < 8" },
    { DECODE_UDP_DGRAM_SHORT_PACKET, "(" CD_UDP_NAME ") Short UDP packet, length field > payload length" },
    { DECODE_UDP_DGRAM_LONG_PACKET, "(" CD_UDP_NAME ") Long UDP packet, length field < payload length" },
    { DECODE_UDP_IPV6_ZERO_CHECKSUM, "(" CD_UDP_NAME ") Invalid IPv6 UDP packet, checksum zero" },
    { DECODE_UDP_LARGE_PACKET, "(" CD_UDP_NAME ") MISC Large UDP Packet" },
    { DECODE_UDP_PORT_ZERO, "(" CD_UDP_NAME ") BAD-TRAFFIC UDP port 0 traffic" },
    { 0, nullptr }
};

class UdpModule : public DecodeModule
{
public:
    UdpModule() : DecodeModule(CD_UDP_NAME, udp_params) {}

    const RuleMap* get_rules() const
    { return udp_rules; }

    bool set(const char*, Value& v, SnortConfig* sc)
    {
        if ( v.is("deep_teredo_inspection") )
        {
            sc->enable_teredo = v.get_long();  // FIXIT-L move to existing bitfield
        }
        else if ( v.is("gtp_ports") )
        {
            ConfigGTPDecoding(sc, v.get_string());
        }
        else if ( v.is("enable_gtp") )
        {
            if ( v.get_bool() )
                sc->enable_gtp = 1;  // FIXIT-L move to existing bitfield
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


    virtual PROTO_ID get_proto_id() { return PROTO_UDP; };
    virtual void get_protocol_ids(std::vector<uint16_t>& v);
    virtual bool decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
        Packet *, uint16_t &lyr_len, uint16_t &next_prot_id);

    virtual bool encode(EncState*, Buffer* out, const uint8_t *raw_in);
    virtual bool update(Packet*, Layer*, uint32_t* len);
    virtual void format(EncodeFlags, const Packet* p, Packet* c, Layer*);
    
};

} // anonymous namespace





static inline void PopUdp (Packet* p);
static inline void UDPMiscTests(Packet *p);




void UdpCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_UDP);
}


bool UdpCodec::decode(const uint8_t *raw_pkt, const uint32_t& raw_len,
    Packet *p, uint16_t &lyr_len, uint16_t &next_prot_id)
{
    uint16_t uhlen;
    u_char fragmented_udp_flag = 0;

    if(raw_len < sizeof(udp::UDPHdr))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                "Truncated UDP header (%d bytes)\n", raw_len););

        codec_events::decoder_event(p, DECODE_UDP_DGRAM_LT_UDPHDR);

        PopUdp(p);
        return false;
    }

    /* set the ptr to the start of the UDP header */
    const udp::UDPHdr* udph = reinterpret_cast<const udp::UDPHdr*>(raw_pkt);
    p->udph = udph;

    if (!(p->decode_flags & DECODE__FRAG))
    {
        uhlen = ntohs(udph->uh_len);
    }
    else if(p->ip_api.is_ip6())
    {
        uint16_t ip_len = ntohs(p->ip_api.len());
        /* subtract the distance from udp header to 1st ip6 extension */
        /* This gives the length of the UDP "payload", when fragmented */
        uhlen = ip_len - ((u_char *)udph - (u_char *)p->ip6_extensions[0].data);
    }
    else
    {
        uint16_t ip_len = ntohs(p->ip_api.len());
        /* Don't forget, IP_HLEN is a word - multiply x 4 */
        uhlen = ip_len - (p->ip_api.hlen() * 4 );
    }
    fragmented_udp_flag = 1;

    /* verify that the header raw_len is a valid value */
    if(uhlen < udp::UDP_HEADER_LEN)
    {
        codec_events::decoder_event(p, DECODE_UDP_DGRAM_INVALID_LENGTH);

        PopUdp(p);
        return false;
    }

    /* make sure there are enough bytes as designated by length field */
    if(uhlen > raw_len)
    {
        codec_events::decoder_event(p, DECODE_UDP_DGRAM_SHORT_PACKET);

        PopUdp(p);
        return false;
    }
    else if(uhlen < raw_len)
    {
        codec_events::decoder_event(p, DECODE_UDP_DGRAM_LONG_PACKET);

        PopUdp(p);
        return false;
    }

    if (ScUdpChecksums())
    {
        /* look at the UDP checksum to make sure we've got a good packet */
        uint16_t csum;
        if(p->ip_api.is_ip4())
        {
            /* Don't do checksum calculation if
             * 1) Fragmented, OR
             * 2) UDP header chksum value is 0.
             */
            if( !fragmented_udp_flag && udph->uh_chk )
            {
                checksum::Pseudoheader ph;
                const ip::IP4Hdr* ip4h = p->ip_api.get_ip4h();
                ph.sip = ip4h->get_src();
                ph.dip = ip4h->get_dst();
                ph.zero = 0;
                ph.protocol = ip4h->get_proto();
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
            /* Alert on checksum value 0 for ipv6 packets */
            if(!udph->uh_chk)
            {
                csum = 1;
                codec_events::decoder_event(p, DECODE_UDP_IPV6_ZERO_CHECKSUM);
            }
            /* Don't do checksum calculation if
             * 1) Fragmented
             * (UDP checksum is not optional in IP6)
             */
            else if( !fragmented_udp_flag )
            {
                checksum::Pseudoheader6 ph6;
                const ip::IP6Hdr* ip6h = p->ip_api.get_ip6h();
                COPY4(ph6.sip, ip6h->ip6_src.u6_addr32);
                COPY4(ph6.dip, ip6h->ip6_dst.u6_addr32);
                ph6.zero = 0;
                ph6.protocol = ip6h->get_next();
                ph6.len = htons((u_short)raw_len);

                csum = checksum::udp_cksum((uint16_t *)(udph), uhlen, &ph6);
            }
            else
            {
                csum = 0;
            }
        }
        if(csum)
        {
            /* Don't drop the packet if this was ESP or Teredo.
               Just stop decoding. */
            if (p->decode_flags & DECODE__UNSURE_ENCAP)
            {
                PopUdp(p);
                return false;
            }

            p->error_flags |= PKT_ERR_CKSUM_UDP;
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "Bad UDP Checksum\n"););

            if( ScInlineMode() && ScUdpChecksumDrops() )
            {
                DEBUG_WRAP(DebugMessage(DEBUG_DECODE,
                    "Dropping bad packet (UDP checksum)\n"););
                Active_DropPacket();
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "UDP Checksum: OK\n"););
        }
    }

    /* fill in the printout data structs */
    p->sp = ntohs(udph->uh_sport);
    p->dp = ntohs(udph->uh_dport);
    lyr_len = udp::UDP_HEADER_LEN;


    // set in packet manager
    p->proto_bits |= PROTO_BIT__UDP;
    UDPMiscTests(p);

    if (ScGTPDecoding() &&
         (ScIsGTPPort(p->sp)||ScIsGTPPort(p->dp)))
    {
        if ( !(p->decode_flags & DECODE__FRAG) )
            next_prot_id = PROTOCOL_GTP;
    }
    else if (teredo::is_teredo_port(p->sp) ||
        teredo::is_teredo_port(p->dp) ||
        ScDeepTeredoInspection())
    {
        if ( !(p->decode_flags & DECODE__FRAG) )
            next_prot_id = PROTOCOL_TEREDO;
    }

    
    return true;
}


/* UDP-layer decoder alerts */
static inline void UDPMiscTests(Packet *p)
{
    if (p->dsize > 4000)
        codec_events::decoder_event(p, DECODE_UDP_LARGE_PACKET);

    if (p->sp == 0 || p->dp == 0)
        codec_events::decoder_event(p, DECODE_UDP_PORT_ZERO);
}

/*
 * Function: DecodeUDP(uint8_t *, const uint32_t, Packet *)
 *
 * Purpose: Decode the UDP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct
 *
 * Returns: void function
 */
static inline void PopUdp (Packet* p)
{

    // required for detect.c to short-circuit preprocessing
    if ( !p->dsize )
        p->dsize = p->ip_api.pay_len();
}

/******************************************************************
 ******************** E N C O D E R  ******************************
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



bool UdpCodec::encode (EncState* enc, Buffer* out, const uint8_t* raw_in)
{   
    const ip::IpApi* const ip_api = &enc->p->ip_api;

    if (enc->p->proto_bits & PROTO_BIT__GTP)
    {
        const udp::UDPHdr* hi = reinterpret_cast<const udp::UDPHdr*>(raw_in);
        udp::UDPHdr* ho;

        if (!update_buffer(out, sizeof(*ho)))
            return false;

        ho = reinterpret_cast<udp::UDPHdr*>(out->base);

        if ( forward(enc->flags) )
        {
            ho->uh_sport = hi->uh_sport;
            ho->uh_dport = hi->uh_dport;
        }
        else
        {
            ho->uh_sport = hi->uh_dport;
            ho->uh_dport = hi->uh_sport;
        }

        uint16_t len = htons((uint16_t)out->end);
        ho->uh_len = htons((uint16_t)len);
        ho->uh_chk = 0;

        if (ip_api->is_ip4())
        {
            checksum::Pseudoheader ps;
            const IP4Hdr* const ip4h = ip_api->get_ip4h();
            ps.sip = ip4h->get_src();
            ps.dip = ip4h->get_dst();
            ps.zero = 0;
            ps.protocol = IPPROTO_UDP;
            ps.len = ho->uh_len;
            ho->uh_chk = checksum::udp_cksum((uint16_t *)ho, len, &ps);
        }
        else
        {
            checksum::Pseudoheader6 ps6;
            const ip::IP6Hdr* const ip6h = ip_api->get_ip6h();
            memcpy(ps6.sip, ip6h->get_src()->u6_addr8, sizeof(ps6.sip));
            memcpy(ps6.dip, ip6h->get_dst()->u6_addr8, sizeof(ps6.dip));
            ps6.zero = 0;
            ps6.protocol = IPPROTO_UDP;
            ps6.len = ho->uh_len;
            ho->uh_chk = checksum::udp_cksum((uint16_t *)ho, len, &ps6);
        }

        return true;
    }

    // if this is not GTP, we want to return an ICMP unreachable packet
    else if ( ip_api->is_ip4())
    {
        // copied directly from Icmp4Codec::encode()
        uint8_t* p;
        IcmpHdr* ho;
        const uint8_t ip_len = ip_api->get_ip4h()->get_hlen() << 2;

        if (!update_buffer(out, sizeof(*ho) + ip_len + icmp::ICMP_UNREACH_DATA_LEN))
            return false;

        const uint16_t *hi = reinterpret_cast<const uint16_t*>(raw_in);
        ho = reinterpret_cast<IcmpHdr*>(out->base);

        enc->proto = IPPROTO_ID_ICMPV4;
        ho->type = icmp::IcmpType::DEST_UNREACH;
        ho->code = ip_util::get_icmp4_code(enc->type);
        ho->cksum = 0;
        ho->unused = 0;

        // copy original ip header
        p = out->base + sizeof(IcmpHdr);
        memcpy(p, ip_api->get_ip4h(), ip_len);

        // copy first 8 octets of original ip data (ie udp header)
        p += ip_len;
        memcpy(p, hi, icmp::ICMP_UNREACH_DATA_LEN);

        ho->cksum = checksum::icmp_cksum((uint16_t *)ho, buff_diff(out, (uint8_t *)ho));
    }
    else
    {
        checksum::Pseudoheader6 ps6;
        IcmpHdr* ho;

        // ip + udp headers are copied separately because there
        // may be intervening extension headers which aren't copied


        // copy first 8 octets of original ip data (ie udp header)
        // TBD: copy up to minimum MTU worth of data
        if (!update_buffer(out, icmp::ICMP_UNREACH_DATA_LEN))
            return false;
        memcpy(out->base, raw_in, icmp::ICMP_UNREACH_DATA_LEN);

        // copy original ip header
        if (!update_buffer(out, ip::IP6_HEADER_LEN))
            return false;

        memcpy(out->base, ip_api->get_ip6h(), ip::IP6_HEADER_LEN);
        ((ip::IP6Hdr*)out->base)->ip6_next = IPPROTO_UDP;


        if (!update_buffer(out, sizeof(*ho)))
            return false;

        ho = reinterpret_cast<IcmpHdr*>(out->base);
        ho->type = static_cast<uint8_t>(icmp::Icmp6Types::UNREACH);
        ho->code = static_cast<uint8_t>(ip_util::get_icmp6_code(enc->type));
        ho->cksum = 0;
        ho->unused = 0;

        // tell next layer this is ICMP6, not udp
        enc->proto = IPPROTO_ID_ICMPV6;


        int len = buff_diff(out, (uint8_t *)ho);
        memcpy(ps6.sip, ip_api->get_ip6h()->get_src()->u6_addr8, sizeof(ps6.sip));
        memcpy(ps6.dip, ip_api->get_ip6h()->get_dst()->u6_addr8, sizeof(ps6.dip));
        ps6.zero = 0;
        ps6.protocol = IPPROTO_ICMPV6;
        ps6.len = htons((uint16_t)(len));

        ho->cksum = checksum::icmp_cksum((uint16_t *)ho, len, &ps6);

    }
    return true;
}

bool UdpCodec::update(Packet* p, Layer* lyr, uint32_t* len)
{
    udp::UDPHdr* h = (udp::UDPHdr*)(lyr->start);

    *len += sizeof(*h) + p->dsize;
    h->uh_len = htons((uint16_t)*len);


    if ( !PacketWasCooked(p) || (p->packet_flags & PKT_REBUILT_FRAG) ) {
        h->uh_chk = 0;

        if (p->ip_api.is_ip4()) {
            checksum::Pseudoheader ps;
            const ip::IP4Hdr* ip4h = p->ip_api.get_ip4h();
            ps.sip = ip4h->get_src();
            ps.dip = ip4h->get_dst();
            ps.zero = 0;
            ps.protocol = IPPROTO_UDP;
            ps.len = htons((uint16_t)*len);
            h->uh_chk = checksum::udp_cksum((uint16_t *)h, *len, &ps);
        }
        else
        {
            checksum::Pseudoheader6 ps6;
            const ip::IP6Hdr* ip6h = p->ip_api.get_ip6h();
            memcpy(ps6.sip, &ip6h->ip6_src.u6_addr32, sizeof(ps6.sip));
            memcpy(ps6.dip, &ip6h->ip6_dst.u6_addr32, sizeof(ps6.dip));
            ps6.zero = 0;
            ps6.protocol = IPPROTO_UDP;
            ps6.len = htons((uint16_t)*len);
            h->uh_chk = checksum::udp_cksum((uint16_t *)h, *len, &ps6);
        }
    }

    return true;
}

void UdpCodec::format (EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    udp::UDPHdr* ch = (udp::UDPHdr*)lyr->start;
    c->udph = ch;

    if ( reverse(f) )
    {
        int i = lyr - c->layers;
        udp::UDPHdr* ph = (udp::UDPHdr*)p->layers[i].start;

        ch->uh_sport = ph->uh_dport;
        ch->uh_dport = ph->uh_sport;
    }
    c->sp = ntohs(ch->uh_sport);
    c->dp = ntohs(ch->uh_dport);
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
