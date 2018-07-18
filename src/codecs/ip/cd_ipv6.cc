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
// cd_ipv6.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sfbpf_dlt.h>

#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "log/text_log.h"
#include "main/snort_config.h"
#include "packet_io/active.h"

using namespace snort;

#define CD_IPV6_NAME "ipv6"
#define CD_IPV6_HELP_STR "support for Internet protocol v6"
#define CD_IPV6_HELP ADD_DLT(CD_IPV6_HELP_STR, DLT_IPV6)

namespace
{
static const RuleMap ipv6_rules[] =
{
    { DECODE_IPV6_MIN_TTL, "IPv6 packet below TTL limit" },
    { DECODE_IPV6_IS_NOT, "IPv6 header claims to not be IPv6" },
    { DECODE_IPV6_TRUNCATED_EXT, "IPv6 truncated extension header" },
    { DECODE_IPV6_TRUNCATED, "IPv6 truncated header" },
    { DECODE_IPV6_DGRAM_LT_IPHDR, "IPv6 datagram length < header field" },
    { DECODE_IPV6_DGRAM_GT_CAPLEN, "IPv6 datagram length > captured length" },
    { DECODE_IPV6_DST_ZERO, "IPv6 packet with destination address ::0" },
    { DECODE_IPV6_SRC_MULTICAST, "IPv6 packet with multicast source address" },
    { DECODE_IPV6_DST_RESERVED_MULTICAST,
      "IPv6 packet with reserved multicast destination address" },
    { DECODE_IPV6_BAD_OPT_TYPE, "IPv6 header includes an undefined option type" },
    { DECODE_IPV6_BAD_MULTICAST_SCOPE,
      "IPv6 address includes an unassigned multicast scope value" },
    { DECODE_IPV6_BAD_NEXT_HEADER,
      "IPv6 header includes an invalid value for the 'next header' field" },
    { DECODE_IPV6_ROUTE_AND_HOPBYHOP,
      "IPv6 header includes a routing extension header followed by a hop-by-hop header" },
    { DECODE_IPV6_TWO_ROUTE_HEADERS, "IPv6 header includes two routing extension headers" },
    { DECODE_IPV6_DSTOPTS_WITH_ROUTING,
      "IPv6 header has destination options followed by a routing header" },
    { DECODE_IPV6_TUNNELED_IPV4_TRUNCATED,
      "IPV6 tunneled over IPv4, IPv6 header truncated, possible Linux kernel attack" },
    { DECODE_IPV6_BAD_OPT_LEN,
      "IPv6 header includes an option which is too big for the containing header" },
    { DECODE_IPV6_UNORDERED_EXTENSIONS, "IPv6 packet includes out-of-order extension headers" },
    { DECODE_IP6_ZERO_HOP_LIMIT, "IPv6 packet has zero hop limit" },
    { DECODE_IPV6_ISATAP_SPOOF, "ISATAP-addressed IPv6 traffic spoofing attempt" },
    { DECODE_IPV6_BAD_FRAG_PKT, "bogus fragmentation packet, possible BSD attack" },
    { DECODE_IPV6_ROUTE_ZERO, "IPv6 routing type 0 extension header" },
    { DECODE_IP6_EXCESS_EXT_HDR, "too many IPv6 extension headers" },
    { DECODE_MIPV6_BAD_PAYLOAD_PROTO,
      "IPv6 mobility header includes an invalid value for the 'payload protocol' field" },
    { 0, nullptr }
};

class Ipv6Module : public CodecModule
{
public:
    Ipv6Module() : CodecModule(CD_IPV6_NAME, CD_IPV6_HELP) { }

    const RuleMap* get_rules() const override
    { return ipv6_rules; }
};

class Ipv6Codec : public Codec
{
public:
    Ipv6Codec() : Codec(CD_IPV6_NAME) { }

    void get_data_link_type(std::vector<int>&) override;
    void get_protocol_ids(std::vector<ProtocolId>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&, Flow*) override;
    void update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
        uint16_t lyr_len, uint32_t& updated_len) override;
    void format(bool reverse, uint8_t* raw_pkt, DecodeData& snort) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;

private:
    void IPV6CheckIsatap(const ip::IP6Hdr* const,
        const DecodeData&,
        const CodecData&);
    void IPV6MiscTests(const DecodeData&, const CodecData&);
    void CheckIPV6Multicast(const ip::IP6Hdr* const, const CodecData&);
    bool CheckTeredoPrefix(const ip::IP6Hdr* const hdr);
};
} // namespace

/********************************************************************
 *************************   CLASS FUNCTIONS ************************
 ********************************************************************/

void Ipv6Codec::get_data_link_type(std::vector<int>& v)
{
    v.push_back(DLT_IPV6);
}

void Ipv6Codec::get_protocol_ids(std::vector<ProtocolId>& v)
{
    v.push_back(ProtocolId::ETHERTYPE_IPV6);
    v.push_back(ProtocolId::IPV6);
}

bool Ipv6Codec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    /* lay the IP struct over the raw data */
    const ip::IP6Hdr* const ip6h =
        reinterpret_cast<const ip::IP6Hdr*>(raw.data);

    if (raw.len < ip::IP6_HEADER_LEN)
    {
        if ((codec.codec_flags & CODEC_UNSURE_ENCAP) == 0)
            codec_event(codec, DECODE_IPV6_TRUNCATED);

        // Taken from prot_ipv4.cc
        codec_event(codec, DECODE_IPV6_TUNNELED_IPV4_TRUNCATED);
        return false;
    }

    /* Verify version in IP6 Header agrees */
    if (ip6h->ver() != 6)
    {
        if ((codec.codec_flags & CODEC_UNSURE_ENCAP) == 0)
            codec_event(codec, DECODE_IPV6_IS_NOT);

        return false;
    }

    if ( SnortConfig::get_conf()->hit_ip_maxlayers(codec.ip_layer_cnt) )
    {
        codec_event(codec, DECODE_IP_MULTIPLE_ENCAPSULATION);
        return false;
    }

    codec.ip_layer_cnt++;
    const uint32_t payload_len = ntohs(ip6h->ip6_payload_len) + ip::IP6_HEADER_LEN;

    if (payload_len != raw.len)
    {
        if (payload_len > raw.len)
        {
            if ((codec.codec_flags & CODEC_UNSURE_ENCAP) == 0)
                codec_event(codec, DECODE_IPV6_DGRAM_GT_CAPLEN);

            return false;
        }
    }

    /* Teredo packets should always use the 2001:0000::/32 prefix, or in some
       cases the link-local prefix fe80::/64.
       Source: RFC 4380, section 2.6 & section 5.2.1

       Checking the addresses will save us from numerous false positives
       when UDP clients use 3544 as their ephemeral port, or "Deep Teredo
       Inspection" is turned on.

       If we ever start decoding more than 2 layers of IP in a packet, this
       check against snort.proto_bits will need to be refactored. */
    if ((codec.codec_flags & CODEC_TEREDO_SEEN) && (!CheckTeredoPrefix(ip6h)))
        return false;

    if ( snort.ip_api.is_ip4() )
    {
        /* If the previous layer was not IP-in-IP, this is not a 6-in-4 tunnel */
        if ( codec.codec_flags & CODEC_NON_IP_TUNNEL )
            codec.codec_flags &= ~CODEC_NON_IP_TUNNEL;
        else if ( SnortConfig::tunnel_bypass_enabled(TUNNEL_6IN4) )
            Active::set_tunnel_bypass();
    }
    else if (snort.ip_api.is_ip6())
    {
        /* If the previous layer was not IP-in-IP, this is not a 6-in-6 tunnel */
        if ( codec.codec_flags & CODEC_NON_IP_TUNNEL )
            codec.codec_flags &= ~CODEC_NON_IP_TUNNEL;
        else if (SnortConfig::tunnel_bypass_enabled(TUNNEL_6IN6))
            Active::set_tunnel_bypass();
    }

    IPV6CheckIsatap(ip6h, snort, codec); // check for isatap before overwriting the ip_api.

    snort.ip_api.set(ip6h);
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

    IPV6MiscTests(snort, codec);
    CheckIPV6Multicast(ip6h, codec);

    if (ip6h->is_valid_next_header() == false)
        codec_event(codec, DECODE_IPV6_BAD_NEXT_HEADER);

    const_cast<uint32_t&>(raw.len) = ip6h->len() + ip::IP6_HEADER_LEN;
    snort.set_pkt_type(PktType::IP);
    codec.next_prot_id = (ProtocolId)ip6h->next();
    codec.lyr_len = ip::IP6_HEADER_LEN;
    codec.curr_ip6_extension = 0;
    codec.ip6_extension_count = 0;
    codec.ip6_csum_proto = ip6h->next();
    codec.codec_flags &= ~CODEC_ROUTING_SEEN;
    codec.proto_bits |= PROTO_BIT__IP;

    return true;
}

void Ipv6Codec::IPV6CheckIsatap(const ip::IP6Hdr* const ip6h,
    const DecodeData& snort,
    const CodecData& codec)
{
    /* Only check for IPv6 over IPv4 */
    if (snort.ip_api.is_ip4() && snort.ip_api.get_ip4h()->proto() == IpProtocol::IPV6)
    {
        uint32_t isatap_interface_id = ntohl(ip6h->ip6_src.u6_addr32[2]) & 0xFCFFFFFF;

        /* ISATAP uses address with prefix fe80:0000:0000:0000:0200:5efe or
           fe80:0000:0000:0000:0000:5efe, followed by the IPv4 address. */
        if (isatap_interface_id == 0x00005EFE)
        {
            if (snort.ip_api.get_src()->get_ip4_value() != ip6h->ip6_src.u6_addr32[3])
                codec_event(codec, DECODE_IPV6_ISATAP_SPOOF);
        }
    }
}

void Ipv6Codec::IPV6MiscTests(const DecodeData& snort, const CodecData& codec)
{
    const SfIp* ip_src = snort.ip_api.get_src();
    const SfIp* ip_dst = snort.ip_api.get_dst();
    /*
     * Some IP Header tests
     * Land Attack(same src/dst ip)
     * Loopback (src or dst in 127/8 block)
     * Modified: 2/22/05-man for High Endian Architecture.
     */
    if (ip_src->fast_eq6(*ip_dst))
    {
        codec_event(codec, DECODE_BAD_TRAFFIC_SAME_SRCDST);
    }

    if (ip_src->is_loopback() || ip_dst->is_loopback())
    {
        codec_event(codec, DECODE_BAD_TRAFFIC_LOOPBACK);
    }

    /* Other decoder alerts for IPv6 addresses
       Added: 5/24/10 (Snort 2.9.0) */
    if (!ip_dst->is_set())
    {
        codec_event(codec, DECODE_IPV6_DST_ZERO);
    }
}

void Ipv6Codec::CheckIPV6Multicast(const ip::IP6Hdr* const ip6h, const CodecData& codec)
{
    ip::MulticastScope multicast_scope;

    if (ip6h->is_src_multicast())
    {
        codec_event(codec, DECODE_IPV6_SRC_MULTICAST);
    }
    if (!ip6h->is_dst_multicast())
    {
        return;
    }

    multicast_scope = ip6h->get_dst_multicast_scope();
    switch (multicast_scope)
    {
    case ip::MulticastScope::RESERVED:
    case ip::MulticastScope::INTERFACE:
    case ip::MulticastScope::LINK:
    case ip::MulticastScope::ADMIN:
    case ip::MulticastScope::SITE:
    case ip::MulticastScope::ORG:
    case ip::MulticastScope::GLOBAL:
        break;

    default:
        codec_event(codec, DECODE_IPV6_BAD_MULTICAST_SCOPE);
    }

    /* Check against assigned multicast addresses. These are listed at:
       http://www.iana.org/assignments/ipv6-multicast-addresses/    */

    /* Multicast addresses only specify the first 16 and last 40 bits.
       Others should be zero. */
    if ((ip6h->ip6_dst.u6_addr16[1] != 0) ||
        (ip6h->ip6_dst.u6_addr16[2] != 0) ||
        (ip6h->ip6_dst.u6_addr16[3] != 0) ||
        (ip6h->ip6_dst.u6_addr16[4] != 0) ||
        (ip6h->ip6_dst.u6_addr8[10] != 0))
    {
        codec_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
        return;
    }

    if (ip6h->is_dst_multicast_scope_reserved())
    {
        // Node-local scope
        if ((ip6h->ip6_dst.u6_addr16[1] != 0) ||
            (ip6h->ip6_dst.u6_addr16[2] != 0) ||
            (ip6h->ip6_dst.u6_addr16[3] != 0) ||
            (ip6h->ip6_dst.u6_addr16[4] != 0) ||
            (ip6h->ip6_dst.u6_addr16[5] != 0) ||
            (ip6h->ip6_dst.u6_addr16[6] != 0))
        {
            codec_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
        else
        {
            switch (ntohl(ip6h->ip6_dst.u6_addr32[3]))
            {
            case 0x00000001:     // All Nodes
            case 0x00000002:     // All Routers
            case 0x000000FB:     // mDNSv6
                break;
            default:
                codec_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
            }
        }
    }
    else if (ip6h->is_dst_multicast_scope_link())
    {
        // Link-local scope
        switch (ntohl(ip6h->ip6_dst.u6_addr32[3]))
        {
        case 0x00000001:     // All Nodes
        case 0x00000002:     // All Routers
        case 0x00000004:     // DVMRP Routers
        case 0x00000005:     // OSPFIGP
        case 0x00000006:     // OSPFIGP Designated Routers
        case 0x00000007:     // ST Routers
        case 0x00000008:     // ST Hosts
        case 0x00000009:     // RIP Routers
        case 0x0000000A:     // EIGRP Routers
        case 0x0000000B:     // Mobile-Agents
        case 0x0000000C:     // SSDP
        case 0x0000000D:     // All PIMP Routers
        case 0x0000000E:     // RSVP-ENCAPSULATION
        case 0x0000000F:     // UPnP
        case 0x00000012:     // VRRP
        case 0x00000016:     // All MLDv2-capable routers
        case 0x0000006A:     // All-Snoopers
        case 0x0000006B:     // PTP-pdelay
        case 0x0000006C:     // Saratoga
        case 0x0000006D:     // LL-MANET-Routers
        case 0x0000006E:     // IGRS
        case 0x0000006F:     // iADT Discovery
        case 0x000000FB:     // mDNSv6
        case 0x00010001:     // Link Name
        case 0x00010002:     // All-dhcp-agents
        case 0x00010003:     // Link-local Multicast Name Resolution
        case 0x00010004:     // DTCP Announcement
            break;
        default:
            if ((ip6h->ip6_dst.u6_addr8[11] == 1) &&
                (ip6h->ip6_dst.u6_addr8[12] == 0xFF))
            {
                break;     // Solicited-Node Address
            }
            if ((ip6h->ip6_dst.u6_addr8[11] == 2) &&
                (ip6h->ip6_dst.u6_addr8[12] == 0xFF))
            {
                break;     // Node Information Queries
            }
            codec_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else if (ip6h->is_dst_multicast_scope_site())
    {
        // Site-local scope
        switch (ntohl(ip6h->ip6_dst.u6_addr32[3]))
        {
        case 0x00000002:     // All Routers
        case 0x000000FB:     // mDNSv6
        case 0x00010003:     // All-dhcp-servers
        case 0x00010004:     // Deprecated
        case 0x00010005:     // SL-MANET-ROUTERS
            break;
        default:
            codec_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else if ((ip6h->ip6_dst.u6_addr8[1] & 0xF0) == 0)
    {
        // Variable scope
        switch (ntohl(ip6h->ip6_dst.u6_addr32[3]))
        {
        case 0x0000000C:     // SSDP
        case 0x000000FB:     // mDNSv6
        case 0x00000181:     // PTP-primary
        case 0x00000182:     // PTP-alternate1
        case 0x00000183:     // PTP-alternate2
        case 0x00000184:     // PTP-alternate3
        case 0x0000018C:     // All ACs multicast address
        case 0x00000201:     // "rwho" Group (BSD)
        case 0x00000202:     // SUN RPC PMAPPROC_CALLIT
        case 0x00000204:     // All C1222 Nodes
        case 0x00000300:     // Mbus/IPv6
        case 0x00027FFE:     // SAPv1 Announcements
        case 0x00027FFF:     // SAPv0 Announcements
            break;
        default:
            if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00000100) &&
                (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x00000136))
            {
                break;     // Several addresses assigned in a contiguous block
            }

            if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00000140) &&
                (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x0000014F))
            {
                break;     // EPSON-disc-set
            }

            if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00020000) &&
                (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x00027FFD))
            {
                break;     // Multimedia Conference Calls
            }

            if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00011000) &&
                (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x000113FF))
            {
                break;     // Service Location, Version 2
            }

            if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00028000) &&
                (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x0002FFFF))
            {
                break;     // SAP Dynamic Assignments
            }

            codec_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else if ((ip6h->ip6_dst.u6_addr8[1] & 0xF0) == 0x30)
    {
        // Source-Specific Multicast block
        if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x40000001) &&
            (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x7FFFFFFF))
        {
            return; // IETF consensus
        }
        else if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x80000000) &&
            (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0xFFFFFFFF))
        {
            return; // Dynamically allocated by hosts when needed
        }
        else
        {
            // Other addresses in this block are reserved.
            codec_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else
    {
        /* Addresses not listed above are reserved. */
        codec_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
    }
}

/* Teredo packets need to have one of their IPs use either the Teredo prefix,
   or a link-local prefix (in the case of Router Solicitation messages) */
bool Ipv6Codec::CheckTeredoPrefix(const ip::IP6Hdr* const hdr)
{
    /* Check if src address matches 2001::/32 */
    if ((hdr->ip6_src.u6_addr8[0] == 0x20) &&
        (hdr->ip6_src.u6_addr8[1] == 0x01) &&
        (hdr->ip6_src.u6_addr8[2] == 0x00) &&
        (hdr->ip6_src.u6_addr8[3] == 0x00))
        return true;

    /* Check if src address matches fe80::/64 */
    if ((hdr->ip6_src.u6_addr8[0] == 0xfe) &&
        (hdr->ip6_src.u6_addr8[1] == 0x80) &&
        (hdr->ip6_src.u6_addr8[2] == 0x00) &&
        (hdr->ip6_src.u6_addr8[3] == 0x00) &&
        (hdr->ip6_src.u6_addr8[4] == 0x00) &&
        (hdr->ip6_src.u6_addr8[5] == 0x00) &&
        (hdr->ip6_src.u6_addr8[6] == 0x00) &&
        (hdr->ip6_src.u6_addr8[7] == 0x00))
        return true;

    /* Check if dst address matches 2001::/32 */
    if ((hdr->ip6_dst.u6_addr8[0] == 0x20) &&
        (hdr->ip6_dst.u6_addr8[1] == 0x01) &&
        (hdr->ip6_dst.u6_addr8[2] == 0x00) &&
        (hdr->ip6_dst.u6_addr8[3] == 0x00))
        return true;

    /* Check if dst address matches fe80::/64 */
    if ((hdr->ip6_dst.u6_addr8[0] == 0xfe) &&
        (hdr->ip6_dst.u6_addr8[1] == 0x80) &&
        (hdr->ip6_dst.u6_addr8[2] == 0x00) &&
        (hdr->ip6_dst.u6_addr8[3] == 0x00) &&
        (hdr->ip6_dst.u6_addr8[4] == 0x00) &&
        (hdr->ip6_dst.u6_addr8[5] == 0x00) &&
        (hdr->ip6_dst.u6_addr8[6] == 0x00) &&
        (hdr->ip6_dst.u6_addr8[7] == 0x00))
        return true;

    /* No Teredo prefix found. */
    return false;
}

/******************************************************************
 *********************  L O G G E R  ******************************
*******************************************************************/

void Ipv6Codec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
{
    const ip::IP6Hdr* const ip6h = reinterpret_cast<const ip::IP6Hdr*>(raw_pkt);

    // FIXIT-H this does NOT obfuscate correctly
    if (SnortConfig::obfuscate())
    {
        TextLog_Print(text_log, "x:x:x:x::x:x:x:x -> x:x:x:x::x:x:x:x");
    }
    else
    {
        const ip::snort_in6_addr* const src = ip6h->get_src();
        const ip::snort_in6_addr* const dst = ip6h->get_dst();

        char src_buf[INET6_ADDRSTRLEN];
        char dst_buf[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, src, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET6, dst, dst_buf, sizeof(dst_buf));

        TextLog_Print(text_log, "%s -> %s", src_buf, dst_buf);
    }

    TextLog_NewLine(text_log);
    TextLog_Putc(text_log, '\t');

    TextLog_Print(text_log, "Next:0x%02X TTL:%u TOS:0x%X DgmLen:%u",
        ip6h->next(), ip6h->hop_lim(), ip6h->tos(),
        ip6h->len());
}

/******************************************************************
 *************************  E N C O D E R  ************************
 ******************************************************************/

bool Ipv6Codec::encode(const uint8_t* const raw_in, const uint16_t /*raw_len*/,
    EncState& enc, Buffer& buf, Flow*)
{
    if (!buf.allocate(sizeof(ip::IP6Hdr)))
        return false;

    const ip::IP6Hdr* const hi = reinterpret_cast<const ip::IP6Hdr*>(raw_in);
    ip::IP6Hdr* const ipvh_out = reinterpret_cast<ip::IP6Hdr*>(buf.data());

    if ( enc.next_proto_set() )
        ipvh_out->ip6_next = enc.next_proto;
    else
        ipvh_out->ip6_next = hi->ip6_next;

    if ( enc.forward() )
    {
        memcpy(ipvh_out->ip6_src.u6_addr8, hi->ip6_src.u6_addr8,
            sizeof(ipvh_out->ip6_src.u6_addr8));
        memcpy(ipvh_out->ip6_dst.u6_addr8, hi->ip6_dst.u6_addr8,
            sizeof(ipvh_out->ip6_dst.u6_addr8));
        ipvh_out->ip6_hoplim = enc.get_ttl(hi->ip6_hoplim);
    }
    else
    {
        memcpy(ipvh_out->ip6_src.u6_addr8, hi->ip6_dst.u6_addr8,
            sizeof(ipvh_out->ip6_src.u6_addr8));
        memcpy(ipvh_out->ip6_dst.u6_addr8, hi->ip6_src.u6_addr8,
            sizeof(ipvh_out->ip6_dst.u6_addr8));
        ipvh_out->ip6_hoplim = enc.get_ttl(hi->ip6_hoplim);
    }

    ipvh_out->ip6_vtf = htonl(ntohl(hi->ip6_vtf) & 0xFFF00000);
    ipvh_out->ip6_payload_len = htons(buf.size() - sizeof(ip::IP6Hdr));

    enc.next_proto = IpProtocol::IPV6;
    enc.next_ethertype = ProtocolId::ETHERTYPE_IPV6;
    return true;
}

void Ipv6Codec::update(const ip::IpApi&, const EncodeFlags flags,
    uint8_t* raw_pkt, uint16_t lyr_len, uint32_t& updated_len)
{
    ip::IP6Hdr* h = reinterpret_cast<ip::IP6Hdr*>(raw_pkt);

    // if we didn't trim payload or format this packet,
    // we may not know the actual lengths because not all
    // extension headers are decoded and we stop at frag6.
    // in such case we do not modify the packet length.
    if ( (flags & UPD_MODIFIED) && !(flags & UPD_RESIZED) )
    {
        // FIXIT-H this worked in Snort.  In Snort++, will this be accurate?
        updated_len = ntohs(h->ip6_payload_len) + ip::IP6_HEADER_LEN;
    }
    else
    {
        updated_len += lyr_len;

        // len includes header, remove for payload
        h->ip6_payload_len = htons((uint16_t)(updated_len - ip::IP6_HEADER_LEN));
    }
}

void Ipv6Codec::format(bool reverse, uint8_t* raw_pkt, DecodeData& snort)
{
    ip::IP6Hdr* ip6h = reinterpret_cast<ip::IP6Hdr*>(raw_pkt);

    if ( reverse )
    {
        ip::snort_in6_addr tmp_addr;

        memcpy(&tmp_addr, ip6h->ip6_dst.u6_addr8, sizeof(ip6h->ip6_src.u6_addr8));
        memcpy(ip6h->ip6_dst.u6_addr8, ip6h->ip6_src.u6_addr8, sizeof(ip6h->ip6_src.u6_addr8));
        memcpy(ip6h->ip6_src.u6_addr8, &tmp_addr, sizeof(ip6h->ip6_dst.u6_addr8));
    }

    // set outer to inner so this will always wind pointing to inner
    snort.ip_api.set(ip6h);
    snort.set_pkt_type(PktType::IP);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new Ipv6Module; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new Ipv6Codec(); }

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
        CD_IPV6_NAME,
        CD_IPV6_HELP,
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
const BaseApi* cd_ipv6[] =
#endif
{
    &ipv6_api.base,
    nullptr
};

