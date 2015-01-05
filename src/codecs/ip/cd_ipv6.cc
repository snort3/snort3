/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// cd_ipv6.cc author Josh Rosenbaum <jrosenba@cisco.com>



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <limits>
#include "detection/fpdetect.h"

#include "protocols/ipv6.h"
#include "codecs/codec_module.h"
#include "codecs/codec_events.h"
#include "codecs/ip/ip_util.h"
#include "framework/codec.h"
#include "stream/stream_api.h"
#include "main/snort.h"
#include "packet_io/active.h"
#include "codecs/codec_module.h"
#include "protocols/protocol_ids.h"
#include "protocols/packet_manager.h"
#include "log/text_log.h"
#include "sfip/sf_ip.h"

#define CD_IPV6_NAME "ipv6"
#define CD_IPV6_HELP "support for Internet protocol v6"

namespace
{

static const RuleMap ipv6_rules[] =
{
    { DECODE_IPV6_MIN_TTL, "IPv6 packet below TTL limit" },
    { DECODE_IPV6_IS_NOT, "IPv6 header claims to not be IPv6" },
    { DECODE_IPV6_TRUNCATED_EXT, "IPV6 truncated extension header" },
    { DECODE_IPV6_TRUNCATED, "IPV6 truncated header" },
    { DECODE_IPV6_DGRAM_LT_IPHDR, "IP dgm len < IP Hdr len" },
    { DECODE_IPV6_DGRAM_GT_CAPLEN, "IP dgm len > captured len" },
    { DECODE_IPV6_DST_ZERO, "IPv6 packet with destination address ::0" },
    { DECODE_IPV6_SRC_MULTICAST, "IPv6 packet with multicast source address" },
    { DECODE_IPV6_DST_RESERVED_MULTICAST, "IPv6 packet with reserved multicast destination address" },
    { DECODE_IPV6_BAD_OPT_TYPE, "IPv6 header includes an undefined option type" },
    { DECODE_IPV6_BAD_MULTICAST_SCOPE, "IPv6 address includes an unassigned multicast scope value" },
    { DECODE_IPV6_BAD_NEXT_HEADER, "IPv6 header includes an invalid value for the 'next header' field" },
    { DECODE_IPV6_ROUTE_AND_HOPBYHOP, "IPv6 header includes a routing extension header followed by a hop-by-hop header" },
    { DECODE_IPV6_TWO_ROUTE_HEADERS, "IPv6 header includes two routing extension headers" },
    { DECODE_IPV6_DSTOPTS_WITH_ROUTING, "IPv6 header has destination options followed by a routing header" },
    { DECODE_IPV6_TUNNELED_IPV4_TRUNCATED, "IPV6 tunneled over IPv4, IPv6 header truncated, possible Linux kernel attack" },
    { DECODE_IPV6_BAD_OPT_LEN, "IPv6 header includes an option which is too big for the containing header" },
    { DECODE_IPV6_UNORDERED_EXTENSIONS, "IPv6 packet includes out-of-order extension headers" },
    { DECODE_IP6_ZERO_HOP_LIMIT, "IPV6 packet has zero hop limit" },
    { DECODE_IPV6_ISATAP_SPOOF, "BAD-TRAFFIC ISATAP-addressed IPv6 traffic spoofing attempt" },
    { DECODE_IPV6_BAD_FRAG_PKT, "bogus fragmentation packet, possible BSD attack" },
    { DECODE_IPV6_ROUTE_ZERO, "IPV6 routing type 0 extension header" },
    { DECODE_IP6_EXCESS_EXT_HDR, "too many IP6 extension headers" },
    { 0, nullptr }
};

class Ipv6Module : public CodecModule
{
public:
    Ipv6Module() : CodecModule(CD_IPV6_NAME, CD_IPV6_HELP) {}

    const RuleMap* get_rules() const override
    { return ipv6_rules; }
};


class Ipv6Codec : public Codec
{
public:
    Ipv6Codec() : Codec(CD_IPV6_NAME){};
    ~Ipv6Codec(){};

    void get_protocol_ids(std::vector<uint16_t>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
                        EncState&, Buffer&) override;
    bool update(Packet*, Layer*, uint32_t* len) override;
    void format(EncodeFlags, const Packet* p, Packet* c, Layer*) override;
    void log(TextLog* const, const uint8_t* /*raw_pkt*/,
                    const Packet* const)  override;
};


} // namespace


static inline void IPV6CheckIsatap(const ip::IP6Hdr* const,
                                    const DecodeData&,
                                    const CodecData&);
static inline void IPV6MiscTests(const DecodeData&, const CodecData&);
static void CheckIPV6Multicast(const ip::IP6Hdr* const, const CodecData&);
static inline bool CheckTeredoPrefix(const ip::IP6Hdr* const hdr);

/********************************************************************
 *************************   CLASS FUNCTIONS ************************
 ********************************************************************/

void Ipv6Codec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_IPV6);
    v.push_back(IPPROTO_ID_IPV6);
}


bool Ipv6Codec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    /* lay the IP struct over the raw data */
    const ip::IP6Hdr* const ip6h =
        reinterpret_cast<const ip::IP6Hdr*>(raw.data);

    if(raw.len < ip::IP6_HEADER_LEN)
    {
        if ((codec.codec_flags & CODEC_UNSURE_ENCAP) == 0)
            codec_events::decoder_event(codec, DECODE_IPV6_TRUNCATED);

        // Taken from prot_ipv4.cc
        codec_events::decoder_event(codec, DECODE_IPV6_TUNNELED_IPV4_TRUNCATED);
        return false;
    }


    /* Verify version in IP6 Header agrees */
    if(ip6h->ver() != 6)
    {
        if ((codec.codec_flags & CODEC_UNSURE_ENCAP) == 0)
            codec_events::decoder_event(codec, DECODE_IPV6_IS_NOT);

        return false;
    }

    if ( snort_conf->hit_ip_maxlayers(codec.ip_layer_cnt) )
    {
        codec_events::decoder_event(codec, DECODE_IP_MULTIPLE_ENCAPSULATION);
        return false;
    }

    codec.ip_layer_cnt++;
    const uint32_t payload_len = ntohs(ip6h->ip6_payload_len) + ip::IP6_HEADER_LEN;

    if(payload_len != raw.len)
    {
        if (payload_len > raw.len)
        {
            if ((codec.codec_flags & CODEC_UNSURE_ENCAP) == 0)
                codec_events::decoder_event(codec, DECODE_IPV6_DGRAM_GT_CAPLEN);

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
        /*  If Teredo or GRE seen, this is not an 4in6 tunnel */
        if ( codec.codec_flags & CODEC_NON_IP_TUNNEL )
            codec.codec_flags &= ~CODEC_NON_IP_TUNNEL;
        else if ( ScTunnelBypassEnabled(TUNNEL_6IN4) )
            Active_SetTunnelBypass();
    }

    IPV6CheckIsatap(ip6h, snort, codec); // check for isatap before overwriting the ip_api.

    snort.ip_api.set(ip6h);

    IPV6MiscTests(snort, codec);
    CheckIPV6Multicast(ip6h, codec);

    const_cast<uint32_t&>(raw.len) = ip6h->len() + ip::IP6_HEADER_LEN;
    snort.set_pkt_type(PktType::IP);
    codec.next_prot_id = ip6h->next();
    codec.lyr_len = ip::IP6_HEADER_LEN;
    codec.curr_ip6_extension = 0;
    codec.ip6_extension_count = 0;
    codec.ip6_csum_proto = ip6h->next();
    codec.codec_flags &= ~CODEC_ROUTING_SEEN;
    codec.proto_bits |= PROTO_BIT__IP;

    return true;
}

static inline void IPV6CheckIsatap(const ip::IP6Hdr* const ip6h,
                                    const DecodeData& snort,
                                    const CodecData& codec)
{
    /* Only check for IPv6 over IPv4 */
    if (snort.ip_api.is_ip4() && snort.ip_api.get_ip4h()->proto() == IPPROTO_ID_IPV6)
    {
        uint32_t isatap_interface_id = ntohl(ip6h->ip6_src.u6_addr32[2]) & 0xFCFFFFFF;

        /* ISATAP uses address with prefix fe80:0000:0000:0000:0200:5efe or
           fe80:0000:0000:0000:0000:5efe, followed by the IPv4 address. */
        if (isatap_interface_id == 0x00005EFE)
        {
            if (snort.ip_api.get_src()->ip32[0] != ip6h->ip6_src.u6_addr32[3])
                codec_events::decoder_event(codec, DECODE_IPV6_ISATAP_SPOOF);
        }
    }
}

/* Function: IPV6MiscTests(Packet *p)
 *
 * Purpose: A bunch of IPv6 decoder alerts
 *
 * Arguments: p => the Packet to check
 *
 * Returns: void function
 */
static inline void IPV6MiscTests(const DecodeData& snort, const CodecData& codec)
{
    const sfip_t *ip_src = snort.ip_api.get_src();
    const sfip_t *ip_dst = snort.ip_api.get_dst();
    /*
     * Some IP Header tests
     * Land Attack(same src/dst ip)
     * Loopback (src or dst in 127/8 block)
     * Modified: 2/22/05-man for High Endian Architecture.
     *
     * some points in the code assume an IP of 0.0.0.0 matches anything, but
     * that is not so here.  The sfip_compare makes that assumption for
     * compatibility, but sfip_contains does not.  Hence, sfip_contains
     * is used here in the interrim. */
    if( sfip_contains(ip_src, ip_dst) == SFIP_CONTAINS)
    {
        codec_events::decoder_event(codec, DECODE_BAD_TRAFFIC_SAME_SRCDST);
    }

    if(sfip_is_loopback(ip_src) || sfip_is_loopback(ip_dst))
    {
        codec_events::decoder_event(codec, DECODE_BAD_TRAFFIC_LOOPBACK);
    }

    /* Other decoder alerts for IPv6 addresses
       Added: 5/24/10 (Snort 2.9.0) */
    if (!sfip_is_set(ip_dst))
    {
        codec_events::decoder_event(codec, DECODE_IPV6_DST_ZERO);
    }
}



/* Check for multiple IPv6 Multicast-related alerts */
static void CheckIPV6Multicast(const ip::IP6Hdr* const ip6h, const CodecData& codec)
{
    ip::MulticastScope multicast_scope;

    if (ip6h->is_src_multicast())
    {
        codec_events::decoder_event(codec, DECODE_IPV6_SRC_MULTICAST);
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
            codec_events::decoder_event(codec, DECODE_IPV6_BAD_MULTICAST_SCOPE);
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
        codec_events::decoder_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
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

            codec_events::decoder_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
        else
        {
            switch (ntohl(ip6h->ip6_dst.u6_addr32[3]))
            {
                case 0x00000001: // All Nodes
                case 0x00000002: // All Routers
                case 0x000000FB: // mDNSv6
                    break;
                default:
                    codec_events::decoder_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
            }
        }
    }
    else if (ip6h->is_dst_multicast_scope_link())
    {
        // Link-local scope
        switch (ntohl(ip6h->ip6_dst.u6_addr32[3]))
        {
            case 0x00000001: // All Nodes
            case 0x00000002: // All Routers
            case 0x00000004: // DVMRP Routers
            case 0x00000005: // OSPFIGP
            case 0x00000006: // OSPFIGP Designated Routers
            case 0x00000007: // ST Routers
            case 0x00000008: // ST Hosts
            case 0x00000009: // RIP Routers
            case 0x0000000A: // EIGRP Routers
            case 0x0000000B: // Mobile-Agents
            case 0x0000000C: // SSDP
            case 0x0000000D: // All PIMP Routers
            case 0x0000000E: // RSVP-ENCAPSULATION
            case 0x0000000F: // UPnP
            case 0x00000012: // VRRP
            case 0x00000016: // All MLDv2-capable routers
            case 0x0000006A: // All-Snoopers
            case 0x0000006B: // PTP-pdelay
            case 0x0000006C: // Saratoga
            case 0x0000006D: // LL-MANET-Routers
            case 0x0000006E: // IGRS
            case 0x0000006F: // iADT Discovery
            case 0x000000FB: // mDNSv6
            case 0x00010001: // Link Name
            case 0x00010002: // All-dhcp-agents
            case 0x00010003: // Link-local Multicast Name Resolution
            case 0x00010004: // DTCP Announcement
                break;
            default:
                if ((ip6h->ip6_dst.u6_addr8[11] == 1) &&
                    (ip6h->ip6_dst.u6_addr8[12] == 0xFF))
                {
                    break; // Solicited-Node Address
                }
                if ((ip6h->ip6_dst.u6_addr8[11] == 2) &&
                    (ip6h->ip6_dst.u6_addr8[12] == 0xFF))
                {
                    break; // Node Information Queries
                }
                codec_events::decoder_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else if (ip6h->is_dst_multicast_scope_site())
    {
        // Site-local scope
        switch (ntohl(ip6h->ip6_dst.u6_addr32[3]))
        {
            case 0x00000002: // All Routers
            case 0x000000FB: // mDNSv6
            case 0x00010003: // All-dhcp-servers
            case 0x00010004: // Deprecated
            case 0x00010005: // SL-MANET-ROUTERS
                break;
            default:
                codec_events::decoder_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else if ((ip6h->ip6_dst.u6_addr8[1] & 0xF0) == 0)
    {
        // Variable scope
        switch (ntohl(ip6h->ip6_dst.u6_addr32[3]))
        {
            case 0x0000000C: // SSDP
            case 0x000000FB: // mDNSv6
            case 0x00000181: // PTP-primary
            case 0x00000182: // PTP-alternate1
            case 0x00000183: // PTP-alternate2
            case 0x00000184: // PTP-alternate3
            case 0x0000018C: // All ACs multicast address
            case 0x00000201: // "rwho" Group (BSD)
            case 0x00000202: // SUN RPC PMAPPROC_CALLIT
            case 0x00000204: // All C1222 Nodes
            case 0x00000300: // Mbus/IPv6
            case 0x00027FFE: // SAPv1 Announcements
            case 0x00027FFF: // SAPv0 Announcements
                break;
            default:
                if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00000100) &&
                    (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x00000136))
                {
                    break; // Several addresses assigned in a contiguous block
                }

                if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00000140) &&
                    (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x0000014F))
                {
                    break; // EPSON-disc-set
                }

                if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00020000) &&
                    (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x00027FFD))
                {
                    break; // Multimedia Conference Calls
                }

                if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00011000) &&
                    (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x000113FF))
                {
                    break; // Service Location, Version 2
                }

                if ((ntohl(ip6h->ip6_dst.u6_addr32[3]) >= 0x00028000) &&
                    (ntohl(ip6h->ip6_dst.u6_addr32[3]) <= 0x0002FFFF))
                {
                    break; // SAP Dynamic Assignments
                }

                codec_events::decoder_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
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
            return; // Dynamiclly allocated by hosts when needed
        }
        else
        {
            // Other addresses in this block are reserved.
            codec_events::decoder_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
        }
    }
    else
    {
        /* Addresses not listed above are reserved. */
        codec_events::decoder_event(codec, DECODE_IPV6_DST_RESERVED_MULTICAST);
    }
}


/* Teredo packets need to have one of their IPs use either the Teredo prefix,
   or a link-local prefix (in the case of Router Solicitation messages) */
static inline bool CheckTeredoPrefix(const ip::IP6Hdr* const hdr)
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
                    const Packet* const)
{
    const ip::IP6Hdr* const ip6h = reinterpret_cast<const ip::IP6Hdr*>(raw_pkt);

    // FIXIT-H  -->  This does NOT obfuscate correctly
    if (ScObfuscate())
    {
        TextLog_Print(text_log, "x:x:x:x::x:x:x:x -> x:x:x:x::x:x:x:x");
    }
    else
    {
        const ip::snort_in6_addr* const src = ip6h->get_src();
        const ip::snort_in6_addr* const dst = ip6h->get_dst();

        TextLog_Print(text_log, "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:"
                            "%02X%02X:%02X%02X:%02X%02X -> %02X%02X:%02X%02X:"
                            "%02X%02X:%02X%02X:%02X%02X:%02X%02X",
            (int)src->u6_addr8[0], (int)src->u6_addr8[1], (int)src->u6_addr8[2],
            (int)src->u6_addr8[3], (int)src->u6_addr8[4], (int)src->u6_addr8[5],
            (int)src->u6_addr8[6], (int)src->u6_addr8[7], (int)src->u6_addr8[8],
            (int)src->u6_addr8[9], (int)src->u6_addr8[10], (int)src->u6_addr8[11],
            (int)src->u6_addr8[12], (int)src->u6_addr8[13], (int)src->u6_addr8[14],
            (int)src->u6_addr8[15], (int)dst->u6_addr8[0], (int)dst->u6_addr8[1],
            (int)dst->u6_addr8[2], (int)dst->u6_addr8[3], (int)dst->u6_addr8[4],
            (int)dst->u6_addr8[5], (int)dst->u6_addr8[6], (int)dst->u6_addr8[7],
            (int)dst->u6_addr8[8], (int)dst->u6_addr8[9], (int)dst->u6_addr8[10],
            (int)dst->u6_addr8[11], (int)dst->u6_addr8[12], (int)dst->u6_addr8[13],
            (int)dst->u6_addr8[14], (int)dst->u6_addr8[15]);
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
                        EncState& enc, Buffer& buf)
{
    if (!buf.allocate(sizeof(ip::IP6Hdr)))
        return false;

    const ip::IP6Hdr* const hi = reinterpret_cast<const ip::IP6Hdr*>(raw_in);
    ip::IP6Hdr* const ipvh_out = reinterpret_cast<ip::IP6Hdr*>(buf.base);




    if ( enc.next_proto_set() )
        ipvh_out->ip6_next = enc.next_proto;
    else
        ipvh_out->ip6_next = hi->ip6_next;


    if ( forward(enc.flags) )
    {
        memcpy(ipvh_out->ip6_src.u6_addr8, hi->ip6_src.u6_addr8, sizeof(ipvh_out->ip6_src.u6_addr8));
        memcpy(ipvh_out->ip6_dst.u6_addr8, hi->ip6_dst.u6_addr8, sizeof(ipvh_out->ip6_dst.u6_addr8));
        ipvh_out->ip6_hoplim = enc.get_ttl(hi->ip6_hoplim);
    }
    else
    {
        memcpy(ipvh_out->ip6_src.u6_addr8, hi->ip6_dst.u6_addr8, sizeof(ipvh_out->ip6_src.u6_addr8));
        memcpy(ipvh_out->ip6_dst.u6_addr8, hi->ip6_src.u6_addr8, sizeof(ipvh_out->ip6_dst.u6_addr8));
        ipvh_out->ip6_hoplim = enc.get_ttl(hi->ip6_hoplim);
    }

    
    ipvh_out->ip6_vtf = htonl(ntohl(hi->ip6_vtf) & 0xFFF00000);
    ipvh_out->ip6_payload_len = htons(buf.size());

    enc.next_proto = IPPROTO_ID_IPV6;
    enc.next_ethertype = ETHERTYPE_IPV6;
    return true;
}

bool Ipv6Codec::update(Packet* p, Layer* lyr, uint32_t* len)
{
    ip::IP6Hdr* h = (ip::IP6Hdr*)(lyr->start);

    // if we didn't trim payload or format this packet,
    // we may not know the actual lengths because not all
    // extension headers are decoded and we stop at frag6.
    // in such case we do not modify the packet length.
    if ( (p->packet_flags & PKT_MODIFIED)
#ifdef NORMALIZER
        && !(p->packet_flags & PKT_RESIZED)
#endif
    )
    {
        // FIXIT-M J  --  this worked in Snort.  In Snort++,
        //          will this be accurate?
        *len = ntohs(h->ip6_payload_len) + sizeof(*h);
    }
    else
    {
        *len += lyr->length;

        // len includes header, remove for payload
        h->ip6_payload_len = htons((uint16_t)(*len - sizeof(*h)));
    }
    return true;
}

void Ipv6Codec::format(EncodeFlags f, const Packet* p, Packet* c, Layer* lyr)
{
    ip::IP6Hdr* ch = reinterpret_cast<ip::IP6Hdr*>(
                            const_cast<uint8_t*>(lyr->start));

    if ( reverse(f) )
    {
        int i = lyr - c->layers;
        ip::IP6Hdr* ph = (ip::IP6Hdr*)p->layers[i].start;

        memcpy(ch->ip6_src.u6_addr8, ph->ip6_dst.u6_addr8, sizeof(ch->ip6_src.u6_addr8));
        memcpy(ch->ip6_dst.u6_addr8, ph->ip6_src.u6_addr8, sizeof(ch->ip6_dst.u6_addr8));
    }

    // set outer to inner so this will always wind pointing to inner
    c->ptrs.ip_api.set(ch);
    c->ptrs.set_pkt_type(PktType::IP);
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

static void dtor(Codec *cd)
{ delete cd; }

static const CodecApi ipv6_api =
{
    {
        PT_CODEC,
        CD_IPV6_NAME,
        CD_IPV6_HELP,
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
const BaseApi* cd_ipv6 = &ipv6_api.base;
#endif
