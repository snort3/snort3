//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// cd_ipv4.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sfbpf_dlt.h>

#include <random>

#include "codecs/codec_module.h"
#include "log/log_text.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "packet_io/active.h"
#include "parser/parse_ip.h"
#include "protocols/ip.h"
#include "protocols/ipv4.h"
#include "protocols/ipv4_options.h"
#include "protocols/tcp.h"
#include "sfip/sf_ipvar.h"

#include "checksum.h"

using namespace snort;

#define CD_IPV4_NAME "ipv4"
#define CD_IPV4_HELP_STR "support for Internet protocol v4"
#define CD_IPV4_HELP ADD_DLT(CD_IPV4_HELP_STR, DLT_IPV4)

namespace
{
const PegInfo pegs[]
{
    { CountType::SUM, "bad_checksum", "nonzero ip checksums" },
    { CountType::END, nullptr, nullptr }
};

struct Stats
{
    PegCount bad_cksum;
};

static THREAD_LOCAL Stats stats;
static sfip_var_t* MulticastReservedIp = nullptr;

static const RuleMap ipv4_rules[] =
{
    { DECODE_NOT_IPV4_DGRAM, "not IPv4 datagram" },
    { DECODE_IPV4_INVALID_HEADER_LEN, "IPv4 header length < minimum" },
    { DECODE_IPV4_DGRAM_LT_IPHDR, "IPv4 datagram length < header field" },
    { DECODE_IPV4OPT_BADLEN, "IPv4 options found with bad lengths" },
    { DECODE_IPV4OPT_TRUNCATED, "truncated IPv4 options" },
    { DECODE_IPV4_DGRAM_GT_CAPLEN, "IPv4 datagram length > captured length" },
    { DECODE_ZERO_TTL, "IPv4 packet with zero TTL" },
    { DECODE_BAD_FRAGBITS, "IPv4 packet with bad frag bits (both MF and DF set)" },
    { DECODE_IP4_LEN_OFFSET, "IPv4 packet frag offset + length exceed maximum" },
    { DECODE_IP4_SRC_THIS_NET, "IPv4 packet from 'current net' source address" },
    { DECODE_IP4_DST_THIS_NET, "IPv4 packet to 'current net' dest address" },
    { DECODE_IP4_SRC_MULTICAST, "IPv4 packet from multicast source address" },
    { DECODE_IP4_SRC_RESERVED, "IPv4 packet from reserved source address" },
    { DECODE_IP4_DST_RESERVED, "IPv4 packet to reserved dest address" },
    { DECODE_IP4_SRC_BROADCAST, "IPv4 packet from broadcast source address" },
    { DECODE_IP4_DST_BROADCAST, "IPv4 packet to broadcast dest address" },
    { DECODE_IP4_MIN_TTL, "IPv4 packet below TTL limit" },
    { DECODE_IP4_DF_OFFSET, "IPv4 packet both DF and offset set" },
    { DECODE_IP_RESERVED_FRAG_BIT, "IPv4 reserved bit set" },
    { DECODE_IP_OPTION_SET, "IPv4 option set" },
    { DECODE_IP4_HDR_TRUNC, "truncated IPv4 header" },
    { 0, nullptr }
};

class Ipv4Module : public CodecModule
{
public:
    Ipv4Module() : CodecModule(CD_IPV4_NAME, CD_IPV4_HELP) { }

    const RuleMap* get_rules() const override
    { return ipv4_rules; }

    const PegInfo* get_pegs() const override
    { return pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&stats; }
};

class Ipv4Codec : public Codec
{
public:
    Ipv4Codec() : Codec(CD_IPV4_NAME) { }

    void get_data_link_type(std::vector<int>&) override;
    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&, Flow*) override;
    void update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
        uint16_t lyr_len, uint32_t& updated_len) override;
    void format(bool reverse, uint8_t* raw_pkt, DecodeData& snort) override;

private:
    void IP4AddrTests(const ip::IP4Hdr*, const CodecData&, DecodeData&);
    void IPMiscTests(const ip::IP4Hdr* const ip4h, const CodecData& codec, uint16_t len);
    void DecodeIPOptions(const uint8_t* start, uint8_t& o_len, CodecData& data);
};
}  // namespace

void Ipv4Codec::get_data_link_type(std::vector<int>& v)
{
    v.push_back(DLT_IPV4);
}

void Ipv4Codec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back(ProtocolId::ETHERTYPE_IPV4);
    v.push_back(ProtocolId::IPIP);
}

bool Ipv4Codec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    uint32_t ip_len; /* length from the start of the ip hdr to the pkt end */
    uint16_t hlen;  /* ip header length */

    if (raw.len < ip::IP4_HEADER_LEN)
    {
        if ((codec.codec_flags & CODEC_UNSURE_ENCAP) == 0)
            codec_event(codec, DECODE_IP4_HDR_TRUNC);
        return false;
    }

    if ( snort::SnortConfig::get_conf()->hit_ip_maxlayers(codec.ip_layer_cnt) )
    {
        codec_event(codec, DECODE_IP_MULTIPLE_ENCAPSULATION);
        return false;
    }

    ++codec.ip_layer_cnt;
    /* lay the IP struct over the raw data */
    const ip::IP4Hdr* const iph = reinterpret_cast<const ip::IP4Hdr*>(raw.data);

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if (iph->ver() != 4)
    {
        if ((codec.codec_flags & CODEC_UNSURE_ENCAP) == 0)
            codec_event(codec, DECODE_NOT_IPV4_DGRAM);
        return false;
    }

    ip_len = iph->len();
    hlen = iph->hlen();

    if (hlen < ip::IP4_HEADER_LEN)
    {
        codec_event(codec, DECODE_IPV4_INVALID_HEADER_LEN);
        return false;
    }

    if (ip_len > raw.len)
    {
        codec_event(codec, DECODE_IPV4_DGRAM_GT_CAPLEN);
        // FIXIT-L we should decode this layer if possible instead of stopping now
        // ip6 etc may have similar issues
        return false;
    }
#if 0
    else if (ip_len < len)
    {
        // There is no need to alert when (ip_len < len).
        // Libpcap will capture more bytes than are part of the IP payload.
        // These could be Ethernet trailers, ESP trailers, etc.
    }
#endif

    if (ip_len < hlen)
    {
        codec_event(codec, DECODE_IPV4_DGRAM_LT_IPHDR);
        return false;
    }

    if ( snort.ip_api.is_ip6() )
    {
        /* If the previous layer was not IP-in-IP, this is not a 4-in-6 tunnel */
        if ( codec.codec_flags & CODEC_NON_IP_TUNNEL )
            codec.codec_flags &= ~CODEC_NON_IP_TUNNEL;
        else if ( snort::SnortConfig::tunnel_bypass_enabled(TUNNEL_4IN6) )
            Active::set_tunnel_bypass();
    }
    else if (snort.ip_api.is_ip4())
    {
        /* If the previous layer was not IP-in-IP, this is not a 4-in-4 tunnel */
        if ( codec.codec_flags & CODEC_NON_IP_TUNNEL )
            codec.codec_flags &= ~CODEC_NON_IP_TUNNEL;
        else if (snort::SnortConfig::tunnel_bypass_enabled(TUNNEL_4IN4))
            Active::set_tunnel_bypass();
    }

    // set the api now since this layer has been verified as valid
    snort.ip_api.set(iph);
    // update to real IP when needed
    if ((raw.pkth->flags & DAQ_PKT_FLAG_REAL_ADDRESSES) and codec.ip_layer_cnt == 1)
    {
        SfIp real_src;
        SfIp real_dst;
        real_src.set(&raw.pkth->real_sIP,
            ((raw.pkth->flags & DAQ_PKT_FLAG_REAL_SIP_V6) ? AF_INET6 : AF_INET));
        real_dst.set(&raw.pkth->real_dIP,
            ((raw.pkth->flags & DAQ_PKT_FLAG_REAL_DIP_V6) ? AF_INET6 : AF_INET));
        snort.ip_api.update(real_src, real_dst);
    }

    /*
     * IP Header tests: Land attack, and Loop back test
     */
    IP4AddrTests(iph, codec, snort);

    if (snort::SnortConfig::ip_checksums())
    {
        /* routers drop packets with bad IP checksums, we don't really
         * need to check them (should make this a command line/config
         * option
         */
        int16_t csum = checksum::ip_cksum((const uint16_t*)iph, hlen);

        if (csum && !codec.is_cooked())
        {
            if ( !(codec.codec_flags & CODEC_UNSURE_ENCAP) )
            {
                stats.bad_cksum++;
                snort.decode_flags |= DECODE_ERR_CKSUM_IP;
            }
            return false;
        }
    }

    /* test for IP options */
    codec.codec_flags &= ~(CODEC_IPOPT_FLAGS);
    uint8_t ip_opt_len = (uint8_t)(hlen - ip::IP4_HEADER_LEN);

    if (ip_opt_len > 0)
        DecodeIPOptions((raw.data + ip::IP4_HEADER_LEN), ip_opt_len, codec);

    /* set the remaining packet length */
    const_cast<uint32_t&>(raw.len) = ip_len;
    ip_len -= hlen;

    /* check for fragmented packets */
    uint16_t frag_off = iph->off_w_flags();

    /*
     * get the values of the reserved, more
     * fragments and don't fragment flags
     */
    if (frag_off & 0x8000)
    {
        codec_event(codec, DECODE_IP_RESERVED_FRAG_BIT);
//        data.decode_flags |= DECODE_RF;  -- flag never needed
    }

    if (frag_off & 0x4000)
        codec.codec_flags |= CODEC_DF;

    if (frag_off & 0x2000)
        snort.decode_flags |= DECODE_MF;

    /* mask off the high bits in the fragment offset field */
    frag_off &= 0x1FFF;

    // to get the real frag_off, we need to multiply by 8. However, since
    // the actual frag_off is never used, we can comment this out
//    frag_off = frag_off << 3;

    if ( (codec.codec_flags & CODEC_DF) && frag_off )
        codec_event(codec, DECODE_IP4_DF_OFFSET);

    if ( frag_off + ip_len > IP_MAXPACKET )
        codec_event(codec, DECODE_IP4_LEN_OFFSET);

    if ( frag_off || (snort.decode_flags & DECODE_MF))
    {
        // FIXIT-L identical to DEFRAG_ANOMALY_ZERO
        if ( !ip_len)
            codec_event(codec, DECODE_ZERO_LENGTH_FRAG);

        snort.decode_flags |= DECODE_FRAG;
    }
    else
    {
        snort.decode_flags &= ~DECODE_FRAG;
    }

    if ( (snort.decode_flags & DECODE_MF) && (codec.codec_flags & CODEC_DF))
        codec_event(codec, DECODE_BAD_FRAGBITS);

    snort.set_pkt_type(PktType::IP);
    codec.proto_bits |= PROTO_BIT__IP;
    IPMiscTests(iph, codec, ip::IP4_HEADER_LEN + ip_opt_len);

    codec.lyr_len = hlen - codec.invalid_bytes;
    codec.curr_ip6_extension = 0;  // necessary since next protos numbers share
    codec.ip6_extension_count = 0; // same space for both ip4 and ip6

    /* if this packet isn't a fragment
     * or if it is, its a UDP packet and offset is 0 */
    if (!(snort.decode_flags & DECODE_FRAG) /*||
        ((frag_off == 0) &&  // FIXIT-H this forces flow to udp instead of ip
         (iph->proto() == IpProtocol::UDP))*/)
    {
        if (to_utype(iph->proto()) >= to_utype(ProtocolId::MIN_UNASSIGNED_IP_PROTO))
            codec_event(codec, DECODE_IP_UNASSIGNED_PROTO);
        else
            codec.next_prot_id = (ProtocolId)iph->proto();
    }

    return true;
}

void Ipv4Codec::IP4AddrTests(
    const ip::IP4Hdr* iph, const CodecData& codec, DecodeData& snort)
{
    uint8_t msb_src, msb_dst;

    // check all 32 bits ...
    if ( iph->ip_src == iph->ip_dst )
    {
        codec_event(codec, DECODE_BAD_TRAFFIC_SAME_SRCDST);
    }

    // check all 32 bits ...
    if (iph->is_src_broadcast())
        codec_event(codec, DECODE_IP4_SRC_BROADCAST);

    if (iph->is_dst_broadcast())
        codec_event(codec, DECODE_IP4_DST_BROADCAST);

    /* Loopback traffic  - don't use htonl for speed reasons -
     * s_addr is always in network order */
#ifdef WORDS_BIGENDIAN
    msb_src = (iph.ip_src >> 24);
    msb_dst = (iph.ip_dst >> 24);
#else
    msb_src = (uint8_t)(iph->ip_src & 0xff);
    msb_dst = (uint8_t)(iph->ip_dst & 0xff);
#endif
    // check the msb ...
    if ( (msb_src == ip::IP4_LOOPBACK) || (msb_dst == ip::IP4_LOOPBACK) )
    {
        codec_event(codec, DECODE_BAD_TRAFFIC_LOOPBACK);
    }
    // check the msb ...
    if ( msb_src == ip::IP4_THIS_NET )
        codec_event(codec, DECODE_IP4_SRC_THIS_NET);

    if ( msb_dst == ip::IP4_THIS_NET )
        codec_event(codec, DECODE_IP4_DST_THIS_NET);

    // check the 'msn' (most significant nibble) ...
    msb_src >>= 4;
    msb_dst >>= 4;

    if ( msb_src == ip::IP4_MULTICAST )
        codec_event(codec, DECODE_IP4_SRC_MULTICAST);

    if ( SnortConfig::is_address_anomaly_check_enabled() )
    {
        if ( msb_src == ip::IP4_RESERVED || sfvar_ip_in(MulticastReservedIp, snort.ip_api.get_src()) )
            codec_event(codec, DECODE_IP4_SRC_RESERVED);

        if ( msb_dst == ip::IP4_RESERVED || sfvar_ip_in(MulticastReservedIp, snort.ip_api.get_dst()) )
            codec_event(codec, DECODE_IP4_DST_RESERVED);
    }
}

/* IPv4-layer decoder rules */
void Ipv4Codec::IPMiscTests(const ip::IP4Hdr* const ip4h, const CodecData& codec, uint16_t len)
{
    /* Yes, it's an ICMP-related vuln in IP options. */
    int cnt = 0;

    /* Alert on IP packets with either 0x07 (Record Route) or 0x44 (Timestamp)
       options that are specially crafted. */
    ip::IpOptionIterator iter(ip4h, (uint8_t)(len));
    for (const ip::IpOptions& opt : iter)
    {
        ++cnt;

        switch (opt.code)
        {
        case ip::IPOptionCodes::EOL:
            --cnt;
            break;

        case ip::IPOptionCodes::RR:
        {
            const uint8_t length = opt.len;
            if (length < 3)
                continue;

            uint8_t pointer = opt.data[0];

            /* If the pointer goes past the end of the data, then the data
               is full. That's okay. */
            if (pointer >= length)
                continue;
            /* If the remaining space in the option isn't a multiple of 4
               bytes, alert. */
            if (((length + 1) - pointer) % 4)
                codec_event(codec, DECODE_ICMP_DOS_ATTEMPT);

            break;
        }
        case ip::IPOptionCodes::TS:
        {
            const uint8_t length = opt.get_len();
            if (length < 2)
                continue;

            uint8_t pointer = opt.data[0];

            /* If the pointer goes past the end of the data, then the data
               is full. That's okay. */
            if (pointer >= length)
                continue;
            /* If the remaining space in the option isn't a multiple of 4
               bytes, alert. */
            if (((length + 1) - pointer) % 4)
                codec_event(codec, DECODE_ICMP_DOS_ATTEMPT);
            /* If there is a timestamp + address, we need a multiple of 8
               bytes instead. */
            if ((opt.data[1] & 0x01) && /* address flag */
                (((length + 1) - pointer) % 8))
                codec_event(codec, DECODE_ICMP_DOS_ATTEMPT);

            break;
        }
        default:
            break;
        }
    }

    if (cnt > 0)
        codec_event(codec, DECODE_IP_OPTION_SET);
}

void Ipv4Codec::DecodeIPOptions(const uint8_t* start, uint8_t& o_len, CodecData& codec)
{
    uint32_t tot_len = 0;
    int code = 0;  /* negative error codes are returned from bad options */

    const ip::IpOptions* option = reinterpret_cast<const ip::IpOptions*>(start);

    while (tot_len < o_len)
    {
        switch (option->code)
        {
        case ip::IPOptionCodes::EOL:
            /* if we hit an EOL, we're done */
            tot_len++;
            codec.invalid_bytes = o_len - tot_len;
            o_len = tot_len;
            return;
        // fall through

        case ip::IPOptionCodes::NOP:
            tot_len++;
            break;

        case ip::IPOptionCodes::RTRALT:
            codec.codec_flags |= CODEC_IPOPT_RTRALT_SEEN;
            goto default_case;

        case ip::IPOptionCodes::RR:
            codec.codec_flags |= CODEC_IPOPT_RR_SEEN;
            // fall through

default_case:
        default:

            if ((tot_len + 1) >= o_len)
                code = tcp::OPT_TRUNC;

            /* RFC says that we MUST have at least this much data */
            else if (option->len < 2)
                code = tcp::OPT_BADLEN;

            else if (tot_len + option->get_len() > o_len)
                /* not enough data to read in a perfect world */
                code = tcp::OPT_TRUNC;

            else if (option->len == 3)
                /* for IGMP alert */
                codec.codec_flags |= CODEC_IPOPT_LEN_THREE;

            if (code < 0)
            {
                /* Yes, we use TCP_OPT_* for the IP option decoder. */
                if (code == tcp::OPT_BADLEN)
                    codec_event(codec, DECODE_IPV4OPT_BADLEN);
                else if (code == tcp::OPT_TRUNC)
                    codec_event(codec, DECODE_IPV4OPT_TRUNCATED);

                codec.invalid_bytes = o_len - tot_len;
                o_len = tot_len;
                return;
            }

            tot_len += option->len;
        }

        option = &(option->next());
    }
}

/******************************************************************
 *********************  L O G G E R  ******************************
*******************************************************************/

struct ip4_addr
{
    union
    {
        uint32_t addr32;
        uint8_t addr8[4];
    };
};

void Ipv4Codec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t lyr_len)
{
    const ip::IP4Hdr* const ip4h = reinterpret_cast<const ip::IP4Hdr*>(raw_pkt);

    // FIXIT-H this does NOT obfuscate correctly
    if (snort::SnortConfig::obfuscate())
    {
        TextLog_Print(text_log, "xxx.xxx.xxx.xxx -> xxx.xxx.xxx.xxx");
    }
    else
    {
        ip4_addr src, dst;
        src.addr32 = ip4h->get_src();
        dst.addr32 = ip4h->get_dst();

        char src_buf[INET_ADDRSTRLEN];
        char dst_buf[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &src, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET, &dst, dst_buf, sizeof(dst_buf));

        TextLog_Print(text_log, "%s -> %s", src_buf, dst_buf);
    }

    TextLog_NewLine(text_log);
    TextLog_Putc(text_log, '\t');

    const uint16_t hlen = ip4h->hlen();
    const uint16_t len = ip4h->len();
    const uint16_t frag_off = ip4h->off_w_flags();
    bool mf_set = false;

    TextLog_Print(text_log, "Next:0x%02X TTL:%u TOS:0x%X ID:%u IpLen:%u DgmLen:%u",
        ip4h->proto(), ip4h->ttl(), ip4h->tos(),
        ip4h->id(), hlen, len);

    /* print the reserved bit if it's set */
    if (frag_off & 0x8000)
        TextLog_Puts(text_log, " RB");

    /* printf more frags/don't frag bits */
    if (frag_off & 0x4000)
        TextLog_Puts(text_log, " DF");

    if (frag_off & 0x2000)
    {
        TextLog_Puts(text_log, " MF");
        mf_set = true;
    }

    /* print IP options */
    if (ip4h->has_options())
    {
        TextLog_Putc(text_log, '\t');
        TextLog_NewLine(text_log);
        LogIpOptions(text_log, ip4h, lyr_len);
    }

    if ( mf_set || (frag_off & 0x1FFF) )
    {
        TextLog_NewLine(text_log);
        TextLog_Putc(text_log, '\t');
        TextLog_Print(text_log, "Frag Offset: 0x%04X   Frag Size: 0x%04X\n",
            (frag_off & 0x1FFF) * 8, (len - hlen));
    }
}

/******************************************************************
 ******************** E N C O D E R  ******************************
*******************************************************************/

static THREAD_LOCAL std::mt19937* thread_rand = nullptr;

static inline uint16_t IpId_Next()
{
    return (*thread_rand)() % UINT16_MAX;
}

/******************************************************************
 ******************** E N C O D E R  ******************************
 ******************************************************************/
bool Ipv4Codec::encode(const uint8_t* const raw_in, const uint16_t /*raw_len*/,
    EncState& enc, Buffer& buf, Flow*)
{
    if (!buf.allocate(ip::IP4_HEADER_LEN))
        return false;

    const ip::IP4Hdr* const ip4h_in = reinterpret_cast<const ip::IP4Hdr*>(raw_in);
    ip::IP4Hdr* const ip4h_out = reinterpret_cast<ip::IP4Hdr*>(buf.data());

    /* IPv4 encoded header is hardcoded 20 bytes */
    ip4h_out->ip_verhl = 0x45;
    ip4h_out->ip_off = 0;
    ip4h_out->ip_id = IpId_Next();
    ip4h_out->ip_tos = ip4h_in->ip_tos;
    ip4h_out->ip_proto = ip4h_in->ip_proto;
    ip4h_out->ip_len = htons((uint16_t)buf.size());
    ip4h_out->ip_csum = 0;

    if ( enc.forward() )
    {
        ip4h_out->ip_src = ip4h_in->ip_src;
        ip4h_out->ip_dst = ip4h_in->ip_dst;
        ip4h_out->ip_ttl = enc.get_ttl(ip4h_in->ip_ttl);
    }
    else
    {
        ip4h_out->ip_src = ip4h_in->ip_dst;
        ip4h_out->ip_dst = ip4h_in->ip_src;
        ip4h_out->ip_ttl = enc.get_ttl(ip4h_in->ip_ttl);
    }

    if ( enc.next_proto_set() )
        ip4h_out->ip_proto = enc.next_proto;

    /* IPv4 encoded header is hardcoded 20 bytes, we save some
     * cycles and use the literal header size for checksum */
    ip4h_out->ip_csum = checksum::ip_cksum((uint16_t*)ip4h_out, ip::IP4_HEADER_LEN);

    enc.next_proto = IpProtocol::IPIP;
    enc.next_ethertype = ProtocolId::ETHERTYPE_IPV4;
    return true;
}

void Ipv4Codec::update(const ip::IpApi&, const EncodeFlags flags,
    uint8_t* raw_pkt, uint16_t /*lyr_len*/, uint32_t& updated_len)
{
    ip::IP4Hdr* h = reinterpret_cast<ip::IP4Hdr*>(raw_pkt);
    uint16_t hlen = h->hlen();

    updated_len += hlen;
    h->set_ip_len((uint16_t)updated_len);

    if ( !(flags & UPD_COOKED) || (flags & UPD_REBUILT_FRAG) )
    {
        h->ip_csum = 0;
        h->ip_csum = checksum::ip_cksum((uint16_t*)h, hlen);
    }
}

void Ipv4Codec::format(bool reverse, uint8_t* raw_pkt, DecodeData& snort)
{
    ip::IP4Hdr* ip4h = reinterpret_cast<ip::IP4Hdr*>(raw_pkt);

    if ( reverse )
    {
        uint32_t tmp_ip = ip4h->ip_src;
        ip4h->ip_src = ip4h->ip_dst;
        ip4h->ip_dst = tmp_ip;
    }

    snort.ip_api.set(ip4h);
    snort.set_pkt_type(PktType::IP);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new Ipv4Module; }

static void mod_dtor(Module* m)
{ delete m; }

static void ipv4_codec_ginit()
{
    // Reserved addresses within multicast address space (See RFC 5771)
    MulticastReservedIp = sfip_var_from_string(
        "[224.1.0.0/16,224.5.0.0/16,224.6.0.0/15,224.8.0.0/13,224.16.0.0/12,"
        "224.32.0.0/11,224.64.0.0/10,224.128.0.0/9,225.0.0.0/8,226.0.0.0/7,"
        "228.0.0.0/6,234.0.0.0/7,236.0.0.0/7,238.0.0.0/8]", "ipv4");

    assert(MulticastReservedIp);
}

static void ipv4_codec_gterm()
{
    if ( MulticastReservedIp )
        sfvar_free(MulticastReservedIp);

    MulticastReservedIp = nullptr;
}

static void ipv4_codec_tinit()
{
    std::random_device rd; // for a good seed
    auto id = rd();

    if (SnortConfig::static_hash())
        id = 1;

    thread_rand = new std::mt19937(id);
}

static void ipv4_codec_tterm()
{
    delete thread_rand;
    thread_rand = nullptr;
}

static Codec* ctor(Module*)
{ return new Ipv4Codec; }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi ipv4_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_IPV4_NAME,
        CD_IPV4_HELP,
        mod_ctor,
        mod_dtor
    },
    ipv4_codec_ginit, // pinit
    ipv4_codec_gterm, // pterm
    ipv4_codec_tinit, // tinit
    ipv4_codec_tterm, // tterm
    ctor, // ctor
    dtor, // dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* cd_ipv4[] =
#endif
{
    &ipv4_api.base,
    nullptr
};

