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
// icmp4.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_ICMP4_H
#define PROTOCOLS_ICMP4_H

#include <cstdint>
#include "protocols/ipv4.h" // for in_addr

namespace snort
{
namespace icmp
{
constexpr uint32_t ICMP_BASE_LEN = 4;
constexpr uint8_t ICMP_UNREACH_DATA_LEN = 8;

// do NOT add 'ICMP_' to the beginning of these const because they
// will overlap with dnet macros

//enum class IcmpType : std::uint8_t {
enum IcmpType : std::uint8_t
{
    ECHOREPLY = 0,
    DEST_UNREACH = 3,
    SOURCE_QUENCH = 4,
    REDIRECT = 5,
    ECHO_4 = 8,
    ROUTER_ADVERTISE = 9,
    ROUTER_SOLICIT = 10,
    TIME_EXCEEDED = 11,
    PARAMETERPROB = 12,
    TIMESTAMP = 13,
    TIMESTAMPREPLY = 14,
    INFO_REQUEST = 15,
    INFO_REPLY = 16,
    ADDRESS = 17,
    ADDRESSREPLY = 18,
//      NR_ICMP_TYPES = 18,
};

//enum class IcmpCode : std::uint8_t {
enum IcmpCode : std::uint8_t
{
    /* Codes for ICMP UNREACHABLES (3) */
    NET_UNREACH = 0,
    HOST_UNREACH = 1,
    PROT_UNREACH = 2,
    PORT_UNREACH = 3,
    FRAG_NEEDED = 4,
    SR_FAILED = 5,
    NET_UNKNOWN = 6,
    HOST_UNKNOWN = 7,
    HOST_ISOLATED = 8,
    PKT_FILTERED_NET = 9,
    PKT_FILTERED_HOST = 10,
    NET_UNR_TOS = 11,
    HOST_UNR_TOS = 12,
    PKT_FILTERED = 13,
    PREC_VIOLATION = 14,
    PREC_CUTOFF = 15,

    /* Code for ICMP Source Quench (4) */
    SOURCE_QUENCH_CODE = 0,

    /* Codes for an ICMP Redirect (5) */
    REDIR_NET = 0,
    REDIR_HOST = 1,
    REDIR_TOS_NET = 2,
    REDIR_TOS_HOST = 3,

    /* Codes for ICMP Echo (8) */
    ECHO_CODE = 0,

    /* Codes for ICMP time exceeded (11) */
    TIMEOUT_TRANSIT = 0,
    TIMEOUT_REASSY = 1,

    /* code for ICMP Parameter Problem (12) */
    PARAM_BADIPHDR = 0,
    PARAM_OPTMISSING = 1,
    PARAM_BAD_LENGTH = 2,
};

struct Icmp4Base
{
    IcmpType type;
    IcmpCode code;
    uint16_t csum;

    union
    {
        uint32_t opt32;
        uint16_t opt16[2];
        uint8_t opt8[4];
    };
};

struct ICMPHdr
{
    IcmpType type;
    IcmpCode code;
    uint16_t csum;

    union
    {
        struct
        {
            uint8_t pptr;
            uint8_t pres1;
            uint16_t pres2;
        } param;

        struct in_addr gwaddr;

        struct idseq
        {
            uint16_t id;
            uint16_t seq;
        } idseq;

        uint32_t sih_void;

        struct pmtu
        {
            uint16_t ipm_void;
            uint16_t nextmtu;
        } pmtu;

        struct rtradv
        {
            uint8_t num_addrs;
            uint8_t wpa;
            uint16_t lifetime;
        } rtradv;
    } icmp_hun;

#define s_icmp_pptr       icmp_hun.param.pptr
#define s_icmp_gwaddr     icmp_hun.gwaddr
#define s_icmp_id         icmp_hun.idseq.id
#define s_icmp_seq        icmp_hun.idseq.seq
#define s_icmp_void       icmp_hun.sih_void
#define s_icmp_pmvoid     icmp_hun.pmtu.ipm_void
#define s_icmp_nextmtu    icmp_hun.pmtu.nextmtu
#define s_icmp_num_addrs  icmp_hun.rtradv.num_addrs
#define s_icmp_wpa        icmp_hun.rtradv.wpa
#define s_icmp_lifetime   icmp_hun.rtradv.lifetime

    union
    {
        /* timestamp */
        struct ts
        {
            uint32_t otime;
            uint32_t rtime;
            uint32_t ttime;
        } ts;

        /* IP header for unreach */
        struct ih_ip
        {
            snort::ip::IP4Hdr* ip;
            /* options and then 64 bits of data */
        } ip;

        struct ra_addr
        {
            uint32_t addr;
            uint32_t preference;
        } radv;

        uint32_t mask;

        char data[1];
    } icmp_dun;
#define s_icmp_otime      icmp_dun.ts.otime
#define s_icmp_rtime      icmp_dun.ts.rtime
#define s_icmp_ttime      icmp_dun.ts.ttime
#define s_icmp_ip         icmp_dun.ih_ip
#define s_icmp_radv       icmp_dun.radv
#define s_icmp_mask       icmp_dun.mask
#define s_icmp_data       icmp_dun.data
};
} //namespace icmp
} // namespace snort

typedef snort::icmp::ICMPHdr ICMPHdr;

#ifndef ICMP_ECHOREPLY
constexpr uint8_t ICMP_ECHOREPLY = 0;    /* Echo Reply                   */
#endif

constexpr uint8_t ICMP_DEST_UNREACH = 3;    /* Destination Unreachable      */
constexpr uint8_t ICMP_SOURCE_QUENCH = 4;    /* Source Quench                */
#ifndef ICMP_REDIRECT
constexpr uint8_t ICMP_REDIRECT = 5;    /* Redirect (change route)      */
#endif
#ifndef ICMP_ECHO
constexpr uint8_t ICMP_ECHO = 8;    /* Echo Request                 */
#endif
constexpr uint8_t ICMP_ROUTER_ADVERTISE = 9;    /* Router Advertisement         */
constexpr uint8_t ICMP_ROUTER_SOLICIT = 10;    /* Router Solicitation          */
constexpr uint8_t ICMP_TIME_EXCEEDED = 11;    /* Time Exceeded                */
constexpr uint8_t ICMP_PARAMETERPROB = 12;    /* Parameter Problem            */
constexpr uint8_t ICMP_TIMESTAMP = 13;    /* Timestamp Request            */
constexpr uint8_t ICMP_TIMESTAMPREPLY = 14;    /* Timestamp Reply              */
constexpr uint8_t ICMP_INFO_REQUEST = 15;    /* Information Request          */
constexpr uint8_t ICMP_INFO_REPLY = 16;    /* Information Reply            */
constexpr uint8_t ICMP_ADDRESS = 17;    /* Address Mask Request         */
constexpr uint8_t ICMP_ADDRESSREPLY = 18;    /* Address Mask Reply           */
constexpr uint8_t NR_ICMP_TYPES = 18;

/* Codes for ICMP UNREACHABLES */
constexpr uint8_t ICMP_NET_UNREACH = 0;    /* Network Unreachable          */
constexpr uint8_t ICMP_HOST_UNREACH = 1;    /* Host Unreachable             */
constexpr uint8_t ICMP_PROT_UNREACH = 2;    /* Protocol Unreachable         */
constexpr uint8_t ICMP_PORT_UNREACH = 3;    /* Port Unreachable             */
constexpr uint8_t ICMP_FRAG_NEEDED = 4;    /* Fragmentation Needed/DF set  */
constexpr uint8_t ICMP_SR_FAILED = 5;    /* Source Route failed          */
constexpr uint8_t ICMP_NET_UNKNOWN = 6;
constexpr uint8_t ICMP_HOST_UNKNOWN = 7;
constexpr uint8_t ICMP_HOST_ISOLATED = 8;
constexpr uint8_t ICMP_PKT_FILTERED_NET = 9;
constexpr uint8_t ICMP_PKT_FILTERED_HOST = 10;
constexpr uint8_t ICMP_NET_UNR_TOS = 11;
constexpr uint8_t ICMP_HOST_UNR_TOS = 12;
constexpr uint8_t ICMP_PKT_FILTERED = 13;    /* Packet filtered */
constexpr uint8_t ICMP_PREC_VIOLATION = 14;    /* Precedence violation */
constexpr uint8_t ICMP_PREC_CUTOFF = 15;    /* Precedence cut off */

constexpr uint8_t ICMP_REDIR_NET = 0;
constexpr uint8_t ICMP_REDIR_HOST = 1;
constexpr uint8_t ICMP_REDIR_TOS_NET = 2;
constexpr uint8_t ICMP_REDIR_TOS_HOST = 3;

constexpr uint8_t ICMP_TIMEOUT_TRANSIT = 0;
constexpr uint8_t ICMP_TIMEOUT_REASSY = 1;

constexpr uint8_t ICMP_PARAM_BADIPHDR = 0;
constexpr uint8_t ICMP_PARAM_OPTMISSING = 1;
constexpr uint8_t ICMP_PARAM_BAD_LENGTH = 2;

#endif /* ICMP4_H */

