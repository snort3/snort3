/*
** Copyright (C) 2013-2013 Sourcefire, Inc.
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
// tcp.h author Josh Rosenbaum <jrosenba@cisco.com>


#ifndef PROTOCOLS_TCP_H
#define PROTOCOLS_TCP_H

#include <cstdint>

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


/* Why are these lil buggers here? Never Used. -- cmg */
#define TCPOLEN_TSTAMP_APPA     (TCPOLEN_TIMESTAMP+2)    /* appendix A / rfc 1323 */
#define TCPOPT_TSTAMP_HDR    \
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)

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


namespace tcp
{


constexpr uint8_t TCP_HEADER_LEN = 20; // this is actually the minimal TCP header lenght
constexpr int OPT_TRUNC = -1;
constexpr int OPT_BADLEN = -2;

struct TCPHdr
{
    uint16_t th_sport;     /* source port */
    uint16_t th_dport;     /* destination port */
    uint32_t th_seq;       /* sequence number */
    uint32_t th_ack;       /* acknowledgement number */
    uint8_t th_offx2;      /* offset and reserved */
    uint8_t th_flags;
    uint16_t th_win;       /* window */
    uint16_t th_sum;       /* checksum */
    uint16_t th_urp;       /* urgent pointer */

    inline uint8_t hdr_len() const
    { return (th_offx2 & 0xf0) >> 2; }

    inline uint8_t off() const
    { return th_offx2 >> 4; }

    inline uint8_t options_len() const
    { return hdr_len() - TCP_HEADER_LEN; }

    inline bool has_options() const
    { return (th_offx2 & 0xf0) == 0x50; }

    inline bool are_flags_set(uint8_t flags) const
    { return (th_flags & flags) == flags; }

    // setters
    inline void set_offset(uint8_t val)
    { th_offx2 = (uint8_t)((th_offx2 & 0x0f) | (val << 4)); }
};


/* more macros for TCP offset */
#define TCP_ISFLAGSET(tcph, flags) (((tcph)->th_flags & (flags)) == (flags))


}  // namespace tcp



#endif /* TCP_H */
