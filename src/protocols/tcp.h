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
// tcp.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_TCP_H
#define PROTOCOLS_TCP_H

#include <arpa/inet.h>

#include <cstdint>

namespace snort
{
namespace tcp
{
// these are bits in th_flags:
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_RES2 TH_ECE  // TBD TH_RES* should be deleted (see log.c)
#define TH_RES1 TH_CWR
#define TH_NORESERVED (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG)

// these are bits in th_offx2:
#define TH_RSV  0x0E  // reserved bits
#define TH_NS   0x01  // ECN nonce bit

/*
 * Default maximum segment size for TCP.
 * With an IP MSS of 576, this is 536,
 * but 512 is probably more convenient.
 * This should be defined as MIN(512, IP_MSS - sizeof (struct tcpiphdr)).
 */

#define TCP_MSS      512
#define TCP_MAXWIN   65535    /* largest value for (unscaled) window */
#define TCP_MAX_WINSHIFT    14    /* maximum window shift */

/*
 * User-settable options (used with setsockopt).
 */
#define TCP_NODELAY   0x01    /* don't delay send to coalesce packets */
#define TCP_MAXSEG    0x02    /* set maximum segment size */
#define SOL_TCP        6    /* TCP level */

#define GET_PKT_SEQ(p) (ntohl((p)->ptrs.tcph->th_seq))

constexpr uint8_t TCP_MIN_HEADER_LEN = 20; // this is actually the minimal TCP header length
constexpr int OPT_TRUNC = -1;
constexpr int OPT_BADLEN = -2;

struct TCPHdr
{
    uint16_t th_sport;     /* source port */
    uint16_t th_dport;     /* destination port */
    uint32_t th_seq;       /* sequence number */
    uint32_t th_ack;       /* acknowledgment number */
    uint8_t th_offx2;      /* offset and reserved */
    uint8_t th_flags;
    uint16_t th_win;       /* window */
    uint16_t th_sum;       /* checksum */
    uint16_t th_urp;       /* urgent pointer */

    /* Formatted data access and booleans */
    inline uint8_t hlen() const
    { return (th_offx2 & 0xf0) >> 2; }

    inline uint8_t off() const
    { return (th_offx2 & 0xf0) >> 2; }

    inline uint8_t options_len() const
    { return hlen() - TCP_MIN_HEADER_LEN; }

    inline uint16_t src_port() const
    { return ntohs(th_sport); }

    inline uint16_t dst_port() const
    { return ntohs(th_dport); }

    inline uint16_t win() const
    { return ntohs(th_win); }

    inline uint16_t cksum() const
    { return ntohs(th_sum); }

    inline uint16_t urp() const
    { return ntohs(th_urp); }

    inline uint32_t seq() const
    { return ntohl(th_seq); }

    inline uint32_t ack() const
    { return ntohl(th_ack); }

    inline bool has_options() const
    { return ((th_offx2 & 0xf0) > 0x50); }

    inline bool are_flags_set(uint8_t flags) const
    { return (th_flags & flags) == flags; }

    inline bool is_syn() const
    { return (th_flags & TH_SYN); }

    inline bool is_syn_only() const
    { return (th_flags & (TH_SYN | TH_ACK)) == TH_SYN; }

    inline bool is_syn_ack() const
    { return are_flags_set(TH_SYN | TH_ACK); }

    inline bool is_ack() const
    { return (th_flags & TH_ACK); }

    inline bool is_psh() const
    { return (th_flags & TH_PUSH); }

    inline bool is_rst() const
    { return (th_flags & TH_RST); }

    inline bool is_fin() const
    { return (th_flags & TH_FIN); }

    /*  raw data access */
    inline uint16_t raw_src_port() const
    { return th_sport; }

    inline uint16_t raw_dst_len() const
    { return th_dport; }

    inline uint32_t raw_seq() const
    { return th_seq; }

    inline uint32_t raw_ack() const
    { return th_ack; }

    inline uint8_t raw_hlen() const
    { return th_offx2 >> 4; }

    inline uint16_t raw_win() const
    { return th_win; }

    inline uint16_t raw_cksum() const
    { return th_sum; }

    inline uint16_t raw_urp() const
    { return th_urp; }

    // setters
    inline void set_offset(uint8_t val)
    { th_offx2 = (uint8_t)((th_offx2 & 0x0f) | (val << 4)); }

    inline void set_urp(uint16_t new_urp)
    { th_urp = htons(new_urp); }

    inline void set_raw_urp(uint16_t new_urp)
    { th_urp = new_urp; }
};
}  // namespace tcp
}  // namespace snort

#endif

