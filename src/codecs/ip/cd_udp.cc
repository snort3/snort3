//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// cd_udp.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <daq.h>

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/messages.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "protocols/teredo.h"
#include "protocols/udp.h"
#include "utils/util.h"

#include "checksum.h"

using namespace snort;

#define CD_UDP_NAME "udp"
#define CD_UDP_HELP "support for user datagram protocol"

namespace
{
const PegInfo pegs[]
{
    { CountType::SUM, "bad_udp4_checksum", "nonzero udp over ipv4 checksums" },
    { CountType::SUM, "bad_udp6_checksum", "nonzero udp over ipv6 checksums" },
    { CountType::SUM, "checksum_bypassed", "checksum calculations bypassed" },
    { CountType::END, nullptr, nullptr }
};

struct Stats
{
    PegCount bad_ip4_cksum;
    PegCount bad_ip6_cksum;
    PegCount cksum_bypassed;
};

static THREAD_LOCAL Stats stats;

static const Parameter udp_params[] =
{
    { "deep_teredo_inspection", Parameter::PT_BOOL, nullptr, "false",
      "look for Teredo on all UDP ports (default is only 3544)" },

    { "gtp_ports", Parameter::PT_BIT_LIST, "65535",
      "2152 3386", "set GTP ports" },

    { "vxlan_ports", Parameter::PT_BIT_LIST, "65535",
      "4789", "set VXLAN ports" },

    { "geneve_ports", Parameter::PT_BIT_LIST, "65535",
      "6081", "set Geneve ports" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap udp_rules[] =
{
    { DECODE_UDP_DGRAM_LT_UDPHDR, "truncated UDP header" },
    { DECODE_UDP_DGRAM_INVALID_LENGTH, "invalid UDP header, length field < 8" },
    { DECODE_UDP_DGRAM_SHORT_PACKET, "short UDP packet, length field > payload length" },
    { DECODE_UDP_DGRAM_LONG_PACKET, "long UDP packet, length field < payload length" },
    { DECODE_UDP_IPV6_ZERO_CHECKSUM, "invalid IPv6 UDP packet, checksum zero" },
    { DECODE_UDP_LARGE_PACKET, "large UDP packet (> 4000 bytes)" },
    { DECODE_UDP_PORT_ZERO, "UDP port 0 traffic" },
    { 0, nullptr }
};

constexpr uint16_t GTP_U_PORT = 2152;
constexpr uint16_t GTP_U_PORT_V0 = 3386;
constexpr uint16_t VXLAN_U_PORT = 4789;
constexpr uint16_t GENEVE_U_PORT = 6081;

class UdpCodecConfig
{
public:
    UdpCodecConfig()
    {
        gtp_ports.set(GTP_U_PORT);
        gtp_ports.set(GTP_U_PORT_V0);
        vxlan_ports.set(VXLAN_U_PORT);
        geneve_ports.set(GENEVE_U_PORT);
    }

    bool deep_teredo_inspection()
    { return enable_teredo; }

    void set_teredo_inspection(bool val)
    { enable_teredo = val; }

    bool gtp_decoding()
    { return gtp_decode; }

    bool is_gtp_port(uint16_t port)
    { return gtp_ports.test(port); }

    bool vxlan_decoding()
    { return vxlan_decode; }

    bool geneve_decoding()
    { return geneve_decode; }

    bool is_vxlan_port(uint16_t port)
    { return vxlan_ports.test(port); }

    bool is_geneve_port(uint16_t port)
    { return geneve_ports.test(port); }

    void set_gtp_ports(const PortBitSet& ports)
    {
        gtp_ports = ports;
        gtp_decode = ports.any();
    }

    void set_vxlan_ports(const PortBitSet& ports)
    {
        vxlan_ports = ports;
        vxlan_decode = ports.any();
    }

    void set_geneve_ports(const PortBitSet& ports)
    {
        geneve_ports = ports;
        geneve_decode = ports.any();
    }

private:
    bool enable_teredo = false;
    PortBitSet gtp_ports;
    PortBitSet vxlan_ports;
    PortBitSet geneve_ports;
    bool gtp_decode = true;
    bool vxlan_decode = true;
    bool geneve_decode = true;
};

class UdpModule : public BaseCodecModule
{
public:
    UdpModule() : BaseCodecModule(CD_UDP_NAME, CD_UDP_HELP, udp_params)
    {
        config = nullptr;
    }

    ~UdpModule() override
    {
        if ( config )
        {
            delete config;
            config = nullptr;
        }
    }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    const RuleMap* get_rules() const override
    { return udp_rules; }

    const PegInfo* get_pegs() const override
    { return pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&stats; }

    UdpCodecConfig* get_data()
    {
        UdpCodecConfig* tmp = config;
        config = nullptr;
        return tmp;
    }

private:
    UdpCodecConfig* config;
};

bool UdpModule::set(const char*, Value& v, SnortConfig*)
{
    PortBitSet ports;

    if ( v.is("deep_teredo_inspection") )
    {
        config->set_teredo_inspection(v.get_bool());
    }
    else if ( v.is("gtp_ports") )
    {
        v.get_bits(ports);
        config->set_gtp_ports(ports);
    }
    else if ( v.is("vxlan_ports") )
    {
        v.get_bits(ports);
        config->set_vxlan_ports(ports);
    }
    else if ( v.is("geneve_ports") )
    {
        v.get_bits(ports);
        config->set_geneve_ports(ports);
    }

    return true;
}

bool UdpModule::begin(const char*, int, SnortConfig*)
{
    assert(!config);
    config = new UdpCodecConfig;
    return true;
}


class UdpCodec : public Codec
{
public:
    UdpCodec(UdpCodecConfig* c) : Codec(CD_UDP_NAME) { config = c; }
    ~UdpCodec() override { delete config; }

    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;

    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&, Flow*) override;
    void update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
        uint16_t lyr_len, uint32_t& updated_len) override;
    void format(bool reverse, uint8_t* raw_pkt, DecodeData& snort) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;

private:

    bool valid_checksum_from_daq(const RawData&);
    bool valid_checksum4(const RawData&, const DecodeData&);
    bool valid_checksum6(const RawData&, const CodecData&, const DecodeData&);

    void UDPMiscTests(const DecodeData&, const CodecData&, uint32_t pay_len);
    UdpCodecConfig* config;
};
} // anonymous namespace

inline bool UdpCodec::valid_checksum_from_daq(const RawData& raw)
{
    const DAQ_PktDecodeData_t* pdd =
        (const DAQ_PktDecodeData_t*) daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_DECODE_DATA);
    if (!pdd || !pdd->flags.bits.l4_checksum || !pdd->flags.bits.udp || !pdd->flags.bits.l4)
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

bool UdpCodec::valid_checksum4(const RawData& raw, const DecodeData& snort)
{
    const ip::IP4Hdr* const ip4h = snort.ip_api.get_ip4h();

    checksum::Pseudoheader ph;
    ph.hdr.sip = ip4h->get_src();
    ph.hdr.dip = ip4h->get_dst();
    ph.hdr.zero = 0;
    ph.hdr.protocol = IpProtocol::UDP;
    ph.hdr.len = htons((uint16_t) raw.len);

    return (checksum::udp_cksum((const uint16_t*) raw.data, raw.len, ph) == 0);
}

bool UdpCodec::valid_checksum6(const RawData& raw, const CodecData& codec, const DecodeData& snort)
{
    const ip::IP6Hdr* const ip6h = snort.ip_api.get_ip6h();

    checksum::Pseudoheader6 ph6;
    COPY4(ph6.hdr.sip, ip6h->get_src()->u6_addr32);
    COPY4(ph6.hdr.dip, ip6h->get_dst()->u6_addr32);
    ph6.hdr.zero = 0;
    ph6.hdr.protocol = codec.ip6_csum_proto;
    ph6.hdr.len = htons((uint16_t) raw.len);

    return (checksum::udp_cksum((const uint16_t*) raw.data, raw.len, ph6) == 0);
}

void UdpCodec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.emplace_back(ProtocolId::UDP);
}

bool UdpCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    uint16_t uhlen;
    bool fragmented_udp_flag = false;

    if (raw.len < udp::UDP_HEADER_LEN)
    {
        codec_event(codec, DECODE_UDP_DGRAM_LT_UDPHDR);
        return false;
    }

    /* set the ptr to the start of the UDP header */
    const udp::UDPHdr* const udph =
        reinterpret_cast<const udp::UDPHdr*>(raw.data);

    // FIXIT-RC since we no longer let UDP fragments through, erase extra code
    if ((snort.decode_flags & DECODE_FRAG) == 0)
    {
        uhlen = ntohs(udph->uh_len);
    }
    else if (snort.ip_api.is_ip6())
    {
        const uint16_t ip_len = snort.ip_api.get_ip6h()->len();
        /* subtract the distance from udp header to 1st ip6 extension
           This gives the length of the UDP "payload", when fragmented */
        uhlen = ip_len - ((const uint8_t*)udph - snort.ip_api.ip_data());
        fragmented_udp_flag = true;
    }
    else
    {
        const ip::IP4Hdr* const ip4h = snort.ip_api.get_ip4h();
        uhlen = ip4h->len() - ip4h->hlen();
        fragmented_udp_flag = true;
    }

    /* verify that the header raw.len is a valid value */
    if (uhlen < udp::UDP_HEADER_LEN)
    {
        codec_event(codec, DECODE_UDP_DGRAM_INVALID_LENGTH);
        return false;
    }

    /* make sure there are enough bytes as designated by length field */
    if (uhlen > raw.len)
    {
        codec_event(codec, DECODE_UDP_DGRAM_SHORT_PACKET);
        return false;
    }
    else if (uhlen < raw.len)
    {
        codec_event(codec, DECODE_UDP_DGRAM_LONG_PACKET);
        return false;
    }

    if (snort::get_network_policy()->udp_checksums() && !valid_checksum_from_daq(raw))
    {
        PegCount* bad_cksum_cnt;
        bool valid;

        /* look at the UDP checksum to make sure we've got a good packet */
        if (snort.ip_api.is_ip4())
        {
            /* Don't do checksum calculation if
             * 1) Fragmented, OR
             * 2) UDP header chksum value is 0.
             */
            if (!fragmented_udp_flag && udph->uh_chk)
                valid = valid_checksum4(raw, snort);
            else
                valid = true;
            bad_cksum_cnt = &stats.bad_ip4_cksum;
        }
        else
        {
            /* Alert on checksum value 0 for ipv6 packets */
            if (!udph->uh_chk)
            {
                valid = false;
                codec_event(codec, DECODE_UDP_IPV6_ZERO_CHECKSUM);
            }
            /* Don't do checksum calculation if
             * 1) Fragmented
             * (UDP checksum is not optional in IP6)
             */
            else if (!fragmented_udp_flag)
                valid = valid_checksum6(raw, codec, snort);
            else
                valid = true;
            bad_cksum_cnt = &stats.bad_ip6_cksum;
        }

        if (!valid && !codec.is_cooked())
        {
            if (!(codec.codec_flags & CODEC_UNSURE_ENCAP))
            {
                (*bad_cksum_cnt)++;
                snort.decode_flags |= DECODE_ERR_CKSUM_UDP;
            }
            return false;
        }
    }

    uint16_t src_port;
    uint16_t dst_port;

    const DAQ_NAPTInfo_t* napti = (const DAQ_NAPTInfo_t*) daq_msg_get_meta(raw.daq_msg, DAQ_PKT_META_NAPT_INFO);
    if (napti && codec.ip_layer_cnt == napti->ip_layer)
    {
        src_port = ntohs(napti->src_port);
        dst_port = ntohs(napti->dst_port);
    }
    else
    {
        src_port = udph->src_port();
        dst_port = udph->dst_port();
    }

    /* fill in the printout data structs */
    snort.udph = udph;
    snort.sp = src_port;
    snort.dp = dst_port;
    codec.lyr_len = udp::UDP_HEADER_LEN;
    codec.proto_bits |= PROTO_BIT__UDP;
    snort.set_pkt_type(PktType::UDP);

    // set in packet manager
    UDPMiscTests(snort, codec, uhlen - udp::UDP_HEADER_LEN);

    if (config->gtp_decoding() and
        (config->is_gtp_port(src_port) || config->is_gtp_port(dst_port)))
    {
        if ( !(snort.decode_flags & DECODE_FRAG) )
            codec.next_prot_id = ProtocolId::GTP;
    }
    else if (teredo::is_teredo_port(src_port) ||
        teredo::is_teredo_port(dst_port) ||
        (config->deep_teredo_inspection()))
    {
        codec.next_prot_id = ProtocolId::TEREDO;
    }
    else if (config->vxlan_decoding() and
        (config->is_vxlan_port(src_port) || config->is_vxlan_port(dst_port)))
    {
        codec.next_prot_id = ProtocolId::VXLAN;
    }
    else if (config->geneve_decoding() and
        (config->is_geneve_port(src_port) || config->is_geneve_port(dst_port)))
    {
        codec.next_prot_id = ProtocolId::GENEVE;
    }

    if (codec.next_prot_id != ProtocolId::FINISHED_DECODE)
        codec.proto_bits |= PROTO_BIT__UDP_TUNNELED;

    return true;
}

/* UDP-layer decoder alerts */
void UdpCodec::UDPMiscTests(const DecodeData& snort,
    const CodecData& codec,
    uint32_t pay_len)
{
    if (pay_len > 4000)
        codec_event(codec, DECODE_UDP_LARGE_PACKET);

    if (snort.sp == 0 || snort.dp == 0)
        codec_event(codec, DECODE_UDP_PORT_ZERO);
}

void UdpCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
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
    EncState& enc, Buffer& buf, Flow*)
{
    // If we enter this function, this packet is some sort of tunnel.

    if (!buf.allocate(udp::UDP_HEADER_LEN))
        return false;

    const udp::UDPHdr* const hi = reinterpret_cast<const udp::UDPHdr*>(raw_in);
    udp::UDPHdr* const udph_out = reinterpret_cast<udp::UDPHdr*>(buf.data());

    // irrespective of direction, for geneve, don't swap the ports
    if ( enc.forward() || config->is_geneve_port(ntohs(hi->uh_dport)) )
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
        const ip::IP4Hdr* const ip4h = ip_api.get_ip4h();
        ps.hdr.sip = ip4h->get_src();
        ps.hdr.dip = ip4h->get_dst();
        ps.hdr.zero = 0;
        ps.hdr.protocol = IpProtocol::UDP;
        ps.hdr.len = udph_out->uh_len;
        udph_out->uh_chk = checksum::udp_cksum((uint16_t*)udph_out, len, ps);
    }
    else if (ip_api.is_ip6())
    {
        checksum::Pseudoheader6 ps6;
        const ip::IP6Hdr* const ip6h = ip_api.get_ip6h();
        memcpy(ps6.hdr.sip, ip6h->get_src()->u6_addr8, sizeof(ps6.hdr.sip));
        memcpy(ps6.hdr.dip, ip6h->get_dst()->u6_addr8, sizeof(ps6.hdr.dip));
        ps6.hdr.zero = 0;
        ps6.hdr.protocol = IpProtocol::UDP;
        ps6.hdr.len = udph_out->uh_len;
        udph_out->uh_chk = checksum::udp_cksum((uint16_t*)udph_out, len, ps6);
    }

    enc.next_proto = IpProtocol::UDP;
    enc.next_ethertype = ProtocolId::ETHERTYPE_NOT_SET;
    return true;
}

void UdpCodec::update(const ip::IpApi& ip_api, const EncodeFlags flags,
    uint8_t* raw_pkt, uint16_t /*lyr_len*/, uint32_t& updated_len)
{
    udp::UDPHdr* h = reinterpret_cast<udp::UDPHdr*>(raw_pkt);

    updated_len += sizeof(*h);
    h->uh_len = htons((uint16_t)updated_len);

    if ( !(flags & UPD_COOKED) || (flags & UPD_REBUILT_FRAG) )
    {
        h->uh_chk = 0;

        if (ip_api.is_ip4())
        {
            checksum::Pseudoheader ps;
            const ip::IP4Hdr* const ip4h = ip_api.get_ip4h();
            ps.hdr.sip = ip4h->get_src();
            ps.hdr.dip = ip4h->get_dst();
            ps.hdr.zero = 0;
            ps.hdr.protocol = IpProtocol::UDP;
            ps.hdr.len = htons((uint16_t)updated_len);
            h->uh_chk = checksum::udp_cksum((uint16_t*)h, updated_len, ps);
        }
        else if (ip_api.is_ip6())
        {
            checksum::Pseudoheader6 ps6;
            const ip::IP6Hdr* const ip6h = ip_api.get_ip6h();
            memcpy(ps6.hdr.sip, ip6h->get_src()->u6_addr32, sizeof(ps6.hdr.sip));
            memcpy(ps6.hdr.dip, ip6h->get_dst()->u6_addr32, sizeof(ps6.hdr.dip));
            ps6.hdr.zero = 0;
            ps6.hdr.protocol = IpProtocol::UDP;
            ps6.hdr.len = htons((uint16_t)updated_len);
            h->uh_chk = checksum::udp_cksum((uint16_t*)h, updated_len, ps6);
        }
    }
}

void UdpCodec::format(bool reverse, uint8_t* raw_pkt, DecodeData& snort)
{
    udp::UDPHdr* udph = reinterpret_cast<udp::UDPHdr*>(raw_pkt);

    if ( reverse )
    {
        uint16_t tmp_port = udph->uh_sport;
        udph->uh_sport = udph->uh_dport;
        udph->uh_dport = tmp_port;
    }

    snort.udph = udph;
    snort.sp = udph->src_port();
    snort.dp = udph->dst_port();
    snort.set_pkt_type(PktType::UDP);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new UdpModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module* m)
{
    UdpModule* mod = (UdpModule*)m;
    // Codecs can be instantiated without modules. In which case use
    // the snort defaults for config.
    UdpCodecConfig* cfg = mod ? (mod->get_data()) : (new UdpCodecConfig());
    return new UdpCodec(cfg);
}

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi udp_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_UDP_NAME,
        CD_UDP_HELP,
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
#else
const BaseApi* cd_udp[] =
#endif
{
    &udp_api.base,
    nullptr
};

