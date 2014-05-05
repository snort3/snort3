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


#ifndef ICMP4_H
#define ICMP4_H

#include <cstdint>
#include "snort_types.h"

namespace icmp4
{

namespace detail
{

const uint32_t ICMP_HEADER_LEN = 4;

} // namespace


// do NOT add 'ICMP_' to the begining of these const because they 
// will overlap with dnet macros


//enum class IcmpType : std::uint8_t {
enum IcmpType : std::uint8_t {
    ECHOREPLY = 0, 
    DEST_UNREACH = 3, 
    SOURCE_QUENCH = 4,  
    REDIRECT = 5,  
    ECHO = 8, 
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
enum IcmpCode : std::uint8_t {
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
    
    /* Code for ICMP Source Quence (4) */
    SOURCE_QUENCH_CODE = 0,

    /* Codes for an ICMP Redirect (5) */
    REDIR_NET = 0,
    REDIR_HOST = 1,
    REDIR_TOS_NET = 2,
    REDIR_TOS_HOST = 3,

    /* Codes for ICMP Echo (8) */
    ECHO_CODE = 0, 

    /* Codes for ICMP time excceeded (11) */
    TIMEOUT_TRANSIT = 0,
    TIMEOUT_REASSY = 1,

    /* code for ICMP Parameter Problem (12) */
    PARAM_BADIPHDR = 0,
    PARAM_OPTMISSING = 1,
    PARAM_BAD_LENGTH = 2,
};

struct ICMPbaseHdr
{
    IcmpType type;
    IcmpCode code;

};

struct ICMPHdr
{
    IcmpType type;
//    union {
//        uint8_t type;
//        _IcmpType enum_type;
//    };
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
            IPHdr *ip;
            /* options and then 64 bits of data */
        } ip;

        struct ra_addr
        {
            uint32_t addr;
            uint32_t preference;
        } radv;

        uint32_t mask;

        char    data[1];

    } icmp_dun;
#define s_icmp_otime      icmp_dun.ts.otime
#define s_icmp_rtime      icmp_dun.ts.rtime
#define s_icmp_ttime      icmp_dun.ts.ttime
#define s_icmp_ip         icmp_dun.ih_ip
#define s_icmp_radv       icmp_dun.radv
#define s_icmp_mask       icmp_dun.mask
#define s_icmp_data       icmp_dun.data
    
} ;




inline bool is_echo_reply(uint32_t type)
{
    return (type == (uint32_t) IcmpType::ECHOREPLY);
}

inline bool is_echo(uint32_t type)
{
    return (type == (uint32_t) IcmpType::ECHO);
}

inline uint32_t hdr_len()
{
  return detail::ICMP_HEADER_LEN;
}

} //namespace icmp4



typedef icmp4::ICMPbaseHdr ICMPbaseHdr;
typedef icmp4::ICMPHdr ICMPHdr;

#ifndef ICMP_ECHOREPLY
const uint8_t ICMP_ECHOREPLY = 0;    /* Echo Reply                   */
#endif

const uint8_t ICMP_DEST_UNREACH = 3;    /* Destination Unreachable      */
const uint8_t  ICMP_SOURCE_QUENCH = 4;    /* Source Quench                */
#ifndef ICMP_REDIRECT
const uint8_t ICMP_REDIRECT = 5;    /* Redirect (change route)      */
#endif
#ifndef ICMP_ECHO
const uint8_t ICMP_ECHO = 8;    /* Echo Request                 */
#endif
const uint8_t  ICMP_ROUTER_ADVERTISE = 9;    /* Router Advertisement         */
const uint8_t  ICMP_ROUTER_SOLICIT = 10;    /* Router Solicitation          */
const uint8_t ICMP_TIME_EXCEEDED = 11;    /* Time Exceeded                */
const uint8_t ICMP_PARAMETERPROB = 12;    /* Parameter Problem            */
const uint8_t ICMP_TIMESTAMP = 13;    /* Timestamp Request            */
const uint8_t  ICMP_TIMESTAMPREPLY = 14;    /* Timestamp Reply              */
const uint8_t  ICMP_INFO_REQUEST = 15;    /* Information Request          */
const uint8_t ICMP_INFO_REPLY = 16;    /* Information Reply            */
const uint8_t ICMP_ADDRESS = 17;    /* Address Mask Request         */
const uint8_t ICMP_ADDRESSREPLY = 18;    /* Address Mask Reply           */
const uint8_t  NR_ICMP_TYPES = 18;

/* Codes for ICMP UNREACHABLES */
const uint8_t  ICMP_NET_UNREACH = 0;    /* Network Unreachable          */
const uint8_t ICMP_HOST_UNREACH = 1;    /* Host Unreachable             */
const uint8_t  ICMP_PROT_UNREACH = 2;    /* Protocol Unreachable         */
const uint8_t ICMP_PORT_UNREACH = 3;    /* Port Unreachable             */
const uint8_t ICMP_FRAG_NEEDED = 4;    /* Fragmentation Needed/DF set  */
const uint8_t ICMP_SR_FAILED = 5;    /* Source Route failed          */
const uint8_t ICMP_NET_UNKNOWN = 6;
const uint8_t  ICMP_HOST_UNKNOWN = 7;
const uint8_t ICMP_HOST_ISOLATED = 8;
const uint8_t  ICMP_PKT_FILTERED_NET = 9;
const uint8_t ICMP_PKT_FILTERED_HOST = 10;
const uint8_t ICMP_NET_UNR_TOS = 11;
const uint8_t ICMP_HOST_UNR_TOS = 12;
const uint8_t ICMP_PKT_FILTERED = 13;    /* Packet filtered */
const uint8_t ICMP_PREC_VIOLATION = 14;    /* Precedence violation */
const uint8_t  ICMP_PREC_CUTOFF = 15;    /* Precedence cut off */
const uint8_t NR_ICMP_UNREACH = 15;   /* instead of hardcoding immediate
                                       * value */

const uint8_t ICMP_REDIR_NET = 0;
const uint8_t ICMP_REDIR_HOST = 1;
const uint8_t ICMP_REDIR_TOS_NET = 2;
const uint8_t ICMP_REDIR_TOS_HOST = 3;

const uint8_t ICMP_TIMEOUT_TRANSIT = 0;
const uint8_t ICMP_TIMEOUT_REASSY = 1;

const uint8_t ICMP_PARAM_BADIPHDR = 0;
const uint8_t ICMP_PARAM_OPTMISSING = 1;
const uint8_t ICMP_PARAM_BAD_LENGTH = 2;

#endif /* ICMP4_H */
