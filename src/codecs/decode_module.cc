/*
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

// decode_module.cc author Russ Combs <rucombs@cisco.com>

#include "decode_module.h"
#include "decode.h"
#include "parser/config_file.h"

//-------------------------------------------------------------------------
// attributes
//-------------------------------------------------------------------------

// FIXIT some of these could move to nap / decoder / traffic policy
static const Parameter decode_params[] =
{
    { "decode_data_link", Parameter::PT_BOOL, nullptr, "false",
      "display the second layer header info" },

    { "decode_esp", Parameter::PT_BOOL, nullptr, "false",
      "enable for inspection of esp traffic that has authentication but not encryption" },

    { "deep_teredo_inspection", Parameter::PT_BOOL, nullptr, "false",
      "look for Teredo on all UDP ports (default is only 3544)" },

    { "enable_gtp", Parameter::PT_BOOL, nullptr, "false",
      "decode GTP encapsulations" },

    { "enable_mpls_multicast", Parameter::PT_BOOL, nullptr, "false",
      "enables support for MPLS multicast" },

    { "enable_mpls_overlapping_ip", Parameter::PT_BOOL, nullptr, "false",
      "enable if private network addresses overlap and must be differentiated by MPLS label(s)" },

    // FIXIT use PT_BIT_LIST
    { "gtp_ports", Parameter::PT_STRING, nullptr,
      "'2152 3386'", "set GTP ports" },

    { "max_mpls_label_chain_len", Parameter::PT_INT, "-1:", "-1",
      "set MPLS stack depth" },

    { "mpls_payload_type", Parameter::PT_ENUM, "eth | ip4 | ip6", "ip4",
      "set encapsulated payload type" },

    { "snap_len", Parameter::PT_INT, "0:65535", "deflt",
      "set snap length (same as -P)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// rule msgs
//-------------------------------------------------------------------------

static const RuleMap decode_rules[] =
{
    { DECODE_NOT_IPV4_DGRAM, "(decode) Not IPv4 datagram" },
    { DECODE_IPV4_INVALID_HEADER_LEN, "(decode) hlen < IP_HEADER_LEN" },
    { DECODE_IPV4_DGRAM_LT_IPHDR, "(decode) IP dgm len < IP Hdr len" },
    { DECODE_IPV4OPT_BADLEN, "(decode) Ipv4 Options found with bad lengths" },
    { DECODE_IPV4OPT_TRUNCATED, "(decode) Truncated Ipv4 Options" },
    { DECODE_IPV4_DGRAM_GT_CAPLEN, "(decode) IP dgm len > captured len" },

    { DECODE_TCP_DGRAM_LT_TCPHDR, "(decode) TCP packet len is smaller than 20 bytes" },
    { DECODE_TCP_INVALID_OFFSET, "(decode) TCP Data Offset is less than 5" },
    { DECODE_TCP_LARGE_OFFSET, "(decode) TCP Header length exceeds packet length" },

    { DECODE_TCPOPT_BADLEN, "(decode) Tcp Options found with bad lengths" },
    { DECODE_TCPOPT_TRUNCATED, "(decode) Truncated Tcp Options" },
    { DECODE_TCPOPT_TTCP, "(decode) T/TCP Detected" },
    { DECODE_TCPOPT_OBSOLETE, "(decode) Obsolete TCP Options found" },
    { DECODE_TCPOPT_EXPERIMENTAL, "(decode) Experimental Tcp Options found" },
    { DECODE_TCPOPT_WSCALE_INVALID, "(decode) Tcp Window Scale Option found with length > 14" },

    { DECODE_UDP_DGRAM_LT_UDPHDR, "(decode) Truncated UDP Header" },
    { DECODE_UDP_DGRAM_INVALID_LENGTH, "(decode) Invalid UDP header, length field < 8" },
    { DECODE_UDP_DGRAM_SHORT_PACKET, "(decode) Short UDP packet, length field > payload length" },
    { DECODE_UDP_DGRAM_LONG_PACKET, "(decode) Long UDP packet, length field < payload length" },

    { DECODE_ICMP_DGRAM_LT_ICMPHDR, "(decode) ICMP Header Truncated" },
    { DECODE_ICMP_DGRAM_LT_TIMESTAMPHDR, "(decode) ICMP Timestamp Header Truncated" },
    { DECODE_ICMP_DGRAM_LT_ADDRHDR, "(decode) ICMP Address Header Truncated" },
    { DECODE_ARP_TRUNCATED, "(decode) Truncated ARP" },
    { DECODE_EAPOL_TRUNCATED, "(decode) Truncated EAP Header" },
    { DECODE_EAPKEY_TRUNCATED, "(decode) EAP Key Truncated" },
    { DECODE_EAP_TRUNCATED, "(decode) EAP Header Truncated" },
    { DECODE_BAD_PPPOE, "(decode) Bad PPPOE frame detected" },
    { DECODE_BAD_VLAN, "(decode) Bad VLAN Frame" },
    { DECODE_BAD_VLAN_ETHLLC, "(decode) Bad LLC header" },
    { DECODE_BAD_VLAN_OTHER, "(decode) Bad Extra LLC Info" },
    { DECODE_BAD_80211_ETHLLC, "(decode) Bad 802.11 LLC header" },
    { DECODE_BAD_80211_OTHER, "(decode) Bad 802.11 Extra LLC Info" },

    { DECODE_BAD_TRH, "(decode) Bad Token Ring Header" },
    { DECODE_BAD_TR_ETHLLC, "(decode) Bad Token Ring ETHLLC Header" },
    { DECODE_BAD_TR_MR_LEN, "(decode) Bad Token Ring MRLENHeader" },
    { DECODE_BAD_TRHMR, "(decode) Bad Token Ring MR Header" },

    { DECODE_BAD_TRAFFIC_LOOPBACK, "(snort decoder) Bad Traffic Loopback IP" },
    { DECODE_BAD_TRAFFIC_SAME_SRCDST, "(snort decoder) Bad Traffic Same Src/Dst IP" },

    { DECODE_GRE_DGRAM_LT_GREHDR, "(snort decoder) GRE header length > payload length" },
    { DECODE_GRE_MULTIPLE_ENCAPSULATION, "(snort decoder) Multiple encapsulations in packet" },
    { DECODE_GRE_INVALID_VERSION, "(snort decoder) Invalid GRE version" },
    { DECODE_GRE_INVALID_HEADER, "(snort decoder) Invalid GRE header" },
    { DECODE_GRE_V1_INVALID_HEADER, "(snort decoder) Invalid GRE v.1 PPTP header" },
    { DECODE_GRE_TRANS_DGRAM_LT_TRANSHDR, "(snort decoder) GRE Trans header length > payload length" },

    { DECODE_ICMP_ORIG_IP_TRUNCATED, "(decode) ICMP Original IP Header Truncated" },
    { DECODE_ICMP_ORIG_IP_VER_MISMATCH, "(decode) ICMP version and Original IP Header versions differ" },
    { DECODE_ICMP_ORIG_DGRAM_LT_ORIG_IP, "(decode) ICMP Original Datagram Length < Original IP Header Length" },
    { DECODE_ICMP_ORIG_PAYLOAD_LT_64, "(decode) ICMP Original IP Payload < 64 bits" },
    { DECODE_ICMP_ORIG_PAYLOAD_GT_576, "(decode) ICMP Origianl IP Payload > 576 bytes" },
    { DECODE_ICMP_ORIG_IP_WITH_FRAGOFFSET, "(decode) ICMP Original IP Fragmented and Offset Not 0" },

    { DECODE_IPV6_MIN_TTL, "(snort decoder) IPv6 packet below TTL limit" },
    { DECODE_IPV6_IS_NOT, "(snort decoder) IPv6 header claims to not be IPv6" },
    { DECODE_IPV6_TRUNCATED_EXT, "(snort decoder) IPV6 truncated extension header" },
    { DECODE_IPV6_TRUNCATED, "(snort decoder) IPV6 truncated header" },
    { DECODE_IPV6_DGRAM_LT_IPHDR, "(decode) IP dgm len < IP Hdr len" },
    { DECODE_IPV6_DGRAM_GT_CAPLEN, "(decode) IP dgm len > captured len" },

    { DECODE_IPV6_DST_ZERO, "(decode) IPv6 packet with destination address ::0" },
    { DECODE_IPV6_SRC_MULTICAST, "(decode) IPv6 packet with multicast source address" },
    { DECODE_IPV6_DST_RESERVED_MULTICAST, "(decode) IPv6 packet with reserved multicast destination address" },
    { DECODE_IPV6_BAD_OPT_TYPE, "(decode) IPv6 header includes an undefined option type" },
    { DECODE_IPV6_BAD_MULTICAST_SCOPE, "(decode) IPv6 address includes an unassigned multicast scope value" },
    { DECODE_IPV6_BAD_NEXT_HEADER, "(decode) IPv6 header includes an invalid value for the \"next header\" field" },
    { DECODE_IPV6_ROUTE_AND_HOPBYHOP, "(decode) IPv6 header includes a routing extension header followed by a hop-by-hop header" },
    { DECODE_IPV6_TWO_ROUTE_HEADERS, "(decode) IPv6 header includes two routing extension headers" },
    { DECODE_IPV6_DSTOPTS_WITH_ROUTING, "(decode) IPv6 header has destination options followed by a routing header" },
    { DECODE_ICMPV6_TOO_BIG_BAD_MTU, "(decode) ICMPv6 packet of type 2 (message too big) with MTU field < 1280" },
    { DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE, "(decode) ICMPv6 packet of type 1 (destination unreachable) with non-RFC 2463 code" },
    { DECODE_ICMPV6_SOLICITATION_BAD_CODE, "(decode) ICMPv6 router solicitation packet with a code not equal to 0" },
    { DECODE_ICMPV6_ADVERT_BAD_CODE, "(decode) ICMPv6 router advertisement packet with a code not equal to 0" },
    { DECODE_ICMPV6_SOLICITATION_BAD_RESERVED, "(decode) ICMPv6 router solicitation packet with the reserved field not equal to 0" },
    { DECODE_ICMPV6_ADVERT_BAD_REACHABLE, "(decode) ICMPv6 router advertisement packet with the reachable time field set > 1 hour" },

    { DECODE_IPV6_TUNNELED_IPV4_TRUNCATED, "(decode) IPV6 tunneled over IPv4, IPv6 header truncated, possible Linux Kernel attack" },

    { DECODE_IP_MULTIPLE_ENCAPSULATION, "(decode) Two or more IP (v4 and/or v6) encapsulation layers present" },

    { DECODE_ESP_HEADER_TRUNC, "(decode) truncated Encapsulated Security Payload (ESP) header" },

    { DECODE_IPV6_BAD_OPT_LEN, "(decode) IPv6 header includes an option which is too big for the containing header" },

    { DECODE_IPV6_UNORDERED_EXTENSIONS, "(decode) IPv6 packet includes out-of-order extension headers" },
    { DECODE_GTP_MULTIPLE_ENCAPSULATION, "(decode) Two or more GTP encapsulation layers present" },
    { DECODE_GTP_BAD_LEN, "(decode) GTP header length is invalid" },
    { DECODE_TCP_XMAS, "(decode) XMAS Attack Detected" },
    { DECODE_TCP_NMAP_XMAS, "(decode) Nmap XMAS Attack Detected" },

    { DECODE_DOS_NAPTHA, "(decode) DOS NAPTHA Vulnerability Detected" },
    { DECODE_SYN_TO_MULTICAST, "(decode) Bad Traffic SYN to multicast address" },
    { DECODE_ZERO_TTL, "(decode) IPV4 packet with zero TTL" },
    { DECODE_BAD_FRAGBITS, "(decode) IPV4 packet with bad frag bits (Both MF and DF set)" },
    { DECODE_UDP_IPV6_ZERO_CHECKSUM, "(decode) Invalid IPv6 UDP packet, checksum zero" },
    { DECODE_IP4_LEN_OFFSET, "(decode) IPV4 packet frag offset + length exceed maximum" },
    { DECODE_IP4_SRC_THIS_NET, "(decode) IPV4 packet from 'current net' source address" },
    { DECODE_IP4_DST_THIS_NET, "(decode) IPV4 packet to 'current net' dest address" },
    { DECODE_IP4_SRC_MULTICAST, "(decode) IPV4 packet from multicast source address" },
    { DECODE_IP4_SRC_RESERVED, "(decode) IPV4 packet from reserved source address" },
    { DECODE_IP4_DST_RESERVED, "(decode) IPV4 packet to reserved dest address" },
    { DECODE_IP4_SRC_BROADCAST, "(decode) IPV4 packet from broadcast source address" },
    { DECODE_IP4_DST_BROADCAST, "(decode) IPV4 packet to broadcast dest address" },
    { DECODE_ICMP4_DST_MULTICAST, "(decode) ICMP4 packet to multicast dest address" },
    { DECODE_ICMP4_DST_BROADCAST, "(decode) ICMP4 packet to broadcast dest address" },
    { DECODE_ICMP4_TYPE_OTHER, "(decode) ICMP4 type other" },
    { DECODE_TCP_BAD_URP, "(decode) TCP urgent pointer exceeds payload length or no payload" },
    { DECODE_TCP_SYN_FIN, "(decode) TCP SYN with FIN" },
    { DECODE_TCP_SYN_RST, "(decode) TCP SYN with RST" },
    { DECODE_TCP_MUST_ACK, "(decode) TCP PDU missing ack for established session" },
    { DECODE_TCP_NO_SYN_ACK_RST, "(decode) TCP has no SYN, ACK, or RST" },
    { DECODE_ETH_HDR_TRUNC, "(decode) truncated eth header" },
    { DECODE_IP4_HDR_TRUNC, "(decode) truncated IP4 header" },
    { DECODE_ICMP4_HDR_TRUNC, "(decode) truncated ICMP4 header" },
    { DECODE_ICMP6_HDR_TRUNC, "(decode) truncated ICMP6 header" },
    { DECODE_IP4_MIN_TTL, "(snort decoder) IPV4 packet below TTL limit" },
    { DECODE_IP6_ZERO_HOP_LIMIT, "(snort decoder) IPV6 packet has zero hop limit" },
    { DECODE_IP4_DF_OFFSET, "(decode) IPV4 packet both DF and offset set" },
    { DECODE_ICMP6_TYPE_OTHER, "(decode) ICMP6 type not decoded" },
    { DECODE_ICMP6_DST_MULTICAST, "(decode) ICMP6 packet to multicast address" },
    { DECODE_TCP_SHAFT_SYNFLOOD, "(decode) DDOS shaft synflood" },
    { DECODE_ICMP_PING_NMAP, "(decode) ICMP PING NMAP" },
    { DECODE_ICMP_ICMPENUM, "(decode) ICMP icmpenum v1.1.1" },
    { DECODE_ICMP_REDIRECT_HOST, "(decode) ICMP redirect host" },
    { DECODE_ICMP_REDIRECT_NET, "(decode) ICMP redirect net" },
    { DECODE_ICMP_TRACEROUTE_IPOPTS, "(decode) ICMP traceroute ipopts" },
    { DECODE_ICMP_SOURCE_QUENCH, "(decode) ICMP Source Quench" },
    { DECODE_ICMP_BROADSCAN_SMURF_SCANNER, "(decode) Broadscan Smurf Scanner" },
    { DECODE_ICMP_DST_UNREACH_ADMIN_PROHIBITED, "(decode) ICMP Destination Unreachable Communication Administratively Prohibited" },
    { DECODE_ICMP_DST_UNREACH_DST_HOST_PROHIBITED, "(decode) ICMP Destination Unreachable Communication with Destination Host is Administratively Prohibited" },
    { DECODE_ICMP_DST_UNREACH_DST_NET_PROHIBITED, "(decode) ICMP Destination Unreachable Communication with Destination Network is Administratively Prohibited" },
    { DECODE_IP_OPTION_SET, "(decode) MISC IP option set" },
    { DECODE_UDP_LARGE_PACKET, "(decode) MISC Large UDP Packet" },
    { DECODE_TCP_PORT_ZERO, "(decode) BAD-TRAFFIC TCP port 0 traffic" },
    { DECODE_UDP_PORT_ZERO, "(decode) BAD-TRAFFIC UDP port 0 traffic" },
    { DECODE_IP_RESERVED_FRAG_BIT, "(decode) BAD-TRAFFIC IP reserved bit set" },
    { DECODE_IP_UNASSIGNED_PROTO, "(decode) BAD-TRAFFIC Unassigned/Reserved IP protocol" },
    { DECODE_IP_BAD_PROTO, "(decode) BAD-TRAFFIC Bad IP protocol" },
    { DECODE_ICMP_PATH_MTU_DOS, "(decode) ICMP PATH MTU denial of service attempt" },
    { DECODE_ICMP_DOS_ATTEMPT, "(decode) BAD-TRAFFIC linux ICMP header dos attempt" },
    { DECODE_IPV6_ISATAP_SPOOF, "(decode) BAD-TRAFFIC ISATAP-addressed IPv6 traffic spoofing attempt" },
    { DECODE_PGM_NAK_OVERFLOW, "(decode) BAD-TRAFFIC PGM nak list overflow attempt" },
    { DECODE_IGMP_OPTIONS_DOS, "(decode) DOS IGMP IP Options validation attempt" },
    { DECODE_IP6_EXCESS_EXT_HDR, "(decode) too many IP6 extension headers" },
    { DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE, "(decode) ICMPv6 packet of type 1 (destination unreachable) with non-RFC 4443 code" },
    { DECODE_IPV6_BAD_FRAG_PKT, "(decode) bogus fragmentation packet. Possible BSD attack" },
    { DECODE_ZERO_LENGTH_FRAG, "(decode) fragment with zero length" },
    { DECODE_ICMPV6_NODE_INFO_BAD_CODE, "(decode) ICMPv6 node info query/response packet with a code greater than 2" },
    { DECODE_IPV6_ROUTE_ZERO, "(snort decoder) IPV6 routing type 0 extension header" },
    { DECODE_ERSPAN_HDR_VERSION_MISMATCH, "(decode) ERSpan Header version mismatch" },
    { DECODE_ERSPAN2_DGRAM_LT_HDR, "(decode) captured < ERSpan Type2 Header Length" },
    { DECODE_ERSPAN3_DGRAM_LT_HDR, "(decode) captured < ERSpan Type3 Header Length" },

    { DECODE_BAD_MPLS, "(decode) Bad MPLS Frame" },
    { DECODE_BAD_MPLS_LABEL0, "(decode) MPLS Label 0 Appears in Nonbottom Header" },
    { DECODE_BAD_MPLS_LABEL1, "(decode) MPLS Label 1 Appears in Bottom Header" },
    { DECODE_BAD_MPLS_LABEL2, "(decode) MPLS Label 2 Appears in Nonbottom Header" },
    { DECODE_BAD_MPLS_LABEL3, "(decode) MPLS Label 3 Appears in Header" },
    { DECODE_MPLS_RESERVED_LABEL, "(decode) MPLS Label 4, 5,.. or 15 Appears in Header" },
    { DECODE_MPLS_LABEL_STACK, "(decode) Too Many MPLS headers" },

    { 0, nullptr }
};

//-------------------------------------------------------------------------
// decode module
//-------------------------------------------------------------------------

DecodeModule::DecodeModule() :
    Module("decode", decode_params, decode_rules) { }

bool DecodeModule::set(const char*, Value& v, SnortConfig* sc)
{
    if ( v.is("decode_data_link") )
    {
        if ( v.get_bool() )
            ConfigDecodeDataLink(sc, "");
    }
    else if ( v.is("decode_esp") )
        sc->enable_esp = v.get_bool();

    else if ( v.is("enable_deep_teredo_inspection") )
        sc->enable_teredo = v.get_long();  // FIXIT move to existing bitfield

    else if ( v.is("enable_gtp") )
    {
        if ( v.get_bool() )
            sc->enable_gtp = 1;  // FIXIT move to existing bitfield
    }
    else if ( v.is("enable_mpls_multicast") )
    {
        if ( v.get_bool() )
            sc->run_flags |= RUN_FLAG__MPLS_MULTICAST; // FIXIT move to existing bitfield
    }
    else if ( v.is("enable_mpls_overlapping_ip") )
    {
        if ( v.get_bool() )
            sc->run_flags |= RUN_FLAG__MPLS_OVERLAPPING_IP; // FIXIT move to existing bitfield
    }
    else if ( v.is("gtp_ports") )
        ConfigGTPDecoding(sc, v.get_string());

    else if ( v.is("max_mpls_label_chain_len") )
        sc->mpls_stack_depth = v.get_long();

    else if ( v.is("mpls_payload_type") )
        sc->mpls_payload_type = v.get_long() + 1;

    else if ( v.is("snaplen") )
        ConfigPacketSnaplen(sc, v.get_string());

    else
        return false;

    return true;
}

