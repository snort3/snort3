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


#ifndef TCP_H 
#define TCP_H

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


/* tcp option codes */
#define TOPT_EOL                0x00
#define TOPT_NOP                0x01
#define TOPT_MSS                0x02
#define TOPT_WS                 0x03
#define TOPT_TS                 0x08

namespace tcp
{

namespace detail
{

const uint8_t TCP_HEADER_LEN = 20;

} // namespace detail

const int OPT_TRUNC = -1;
const int OPT_BADLEN = -2;

inline uint8_t hdr_len()
{
    return detail::TCP_HEADER_LEN;
}



/* http://www.iana.org/assignments/tcp-parameters
 *
 * tcp options stuff. used to be in <netinet/tcp.h> but it breaks
 * things on AIX
 */

// enum class TcpOpt{
enum TcpOpt{
    EOL = 0,   /* End of Option List [RFC793] */
    NOP = 1,   /* No-Option [RFC793] */
    MAXSEG = 2,   /* Maximum Segment Size [RFC793] */
    WSCALE = 3,   /* Window scaling option [RFC1323] */
    SACKOK = 4,    /* Experimental [RFC2018]*/
    SACK = 5,    /* Experimental [RFC2018] variable length */
    ECHO = 6,    /* Echo (obsoleted by option 8)      [RFC1072] */
    ECHOREPLY = 7,    /* Echo Reply (obsoleted by option 8)[RFC1072] */
    TIMESTAMP = 8,   /* Timestamp [RFC1323], 10 bytes */
    PARTIAL_PERM = 9,   /* Partial Order Permitted/ Experimental [RFC1693] */
    PARTIAL_SVC = 10,  /*  Partial Order Profile [RFC1693] */
    CC = 11,  /*  T/TCP Connection count  [RFC1644] */
    CC_NEW = 12,  /*  CC.NEW [RFC1644] */
    CC_ECHO = 13,  /*  CC.ECHO [RFC1644] */

    ALTCSUM = 15,  /* TCP Alternate Checksum Data [RFC1146], variable length */
    SKEETER = 16,  /* Skeeter [Knowles] */
    BUBBA = 17,  /* Bubba   [Knowles] */
    TRAILER_CSUM = 18,  /* Trailer Checksum Option [Subbu & Monroe] */
    MD5SIG = 19,  /* MD5 Signature Option [RFC2385] */


    /* Space Communications Protocol Standardization */
    SCPS = 20,  /* Capabilities [Scott] */
    SELNEGACK = 21,  /* Selective Negative Acknowledgements [Scott] */
    RECORDBOUND = 22,  /* Record Boundaries [Scott] */
    CORRUPTION = 23,  /* Corruption experienced [Scott] */
    SNAP = 24,  /* SNAP [Sukonnik] -- anyone have info?*/
    UNASSIGNED = 25,  /* Unassigned (released 12/18/00) */
    COMPRESSION = 26,  /* TCP Compression Filter [Bellovin] */
    /* http://www.research.att.com/~smb/papers/draft-bellovin-tcpcomp-00.txt*/

    AUTH = 29,  /* [RFC5925] - The TCP Authentication Option
                             Intended to replace MD5 Signature Option [RFC2385] */
};


#define TCPOLEN_EOL             1   /* Always one byte */
#define TCPOLEN_NOP             1   /* Always one byte */
#define TCPOLEN_MAXSEG          4   /* Always 4 bytes */
#define TCPOLEN_WSCALE          3   /* 1 byte with logarithmic values */
#define TCPOLEN_SACKOK          2
#define TCPOLEN_ECHO            6    /* 6 bytes  */
#define TCPOLEN_ECHOREPLY       6    /* 6 bytes  */
#define TCPOLEN_TIMESTAMP       10
#define TCPOLEN_PARTIAL_PERM    2   /* Partial Order Permitted/ Experimental [RFC1693] */
#define TCPOLEN_PARTIAL_SVC     3   /*  3 bytes long -- Experimental */

/* atleast decode T/TCP options... */
#define TCPOLEN_CC             6  /* page 17 of rfc1644 */
#define TCPOLEN_CC_NEW         6  /* page 17 of rfc1644 */
#define TCPOLEN_CC_ECHO        6  /* page 17 of rfc1644 */
#define TCPOLEN_TRAILER_CSUM  3
#define TCPOLEN_MD5SIG        18






}  // namespace Tcp



/* delete everything from here to the end of the file (excluding the #endif of course) */

#define TCPOPT_EOL              0   /* End of Option List [RFC793] */
#define TCPOLEN_EOL             1   /* Always one byte */

#define TCPOPT_NOP              1   /* No-Option [RFC793] */
#define TCPOLEN_NOP             1   /* Always one byte */

#define TCPOPT_MAXSEG           2   /* Maximum Segment Size [RFC793] */
#define TCPOLEN_MAXSEG          4   /* Always 4 bytes */

#define TCPOPT_WSCALE           3   /* Window scaling option [RFC1323] */
#define TCPOLEN_WSCALE          3   /* 1 byte with logarithmic values */

#define TCPOPT_SACKOK           4    /* Experimental [RFC2018]*/
#define TCPOLEN_SACKOK          2

#define TCPOPT_SACK             5    /* Experimental [RFC2018] variable length */

#define TCPOPT_ECHO             6    /* Echo (obsoleted by option 8)      [RFC1072] */
#define TCPOLEN_ECHO            6    /* 6 bytes  */

#define TCPOPT_ECHOREPLY        7    /* Echo Reply (obsoleted by option 8)[RFC1072] */
#define TCPOLEN_ECHOREPLY       6    /* 6 bytes  */

#define TCPOPT_TIMESTAMP        8   /* Timestamp [RFC1323], 10 bytes */
#define TCPOLEN_TIMESTAMP       10

#define TCPOPT_PARTIAL_PERM     9   /* Partial Order Permitted/ Experimental [RFC1693] */
#define TCPOLEN_PARTIAL_PERM    2   /* Partial Order Permitted/ Experimental [RFC1693] */

#define TCPOPT_PARTIAL_SVC      10  /*  Partial Order Profile [RFC1693] */
#define TCPOLEN_PARTIAL_SVC     3   /*  3 bytes long -- Experimental */

/* atleast decode T/TCP options... */
#define TCPOPT_CC               11  /*  T/TCP Connection count  [RFC1644] */
#define TCPOPT_CC_NEW           12  /*  CC.NEW [RFC1644] */
#define TCPOPT_CC_ECHO          13  /*  CC.ECHO [RFC1644] */
#define TCPOLEN_CC             6  /* page 17 of rfc1644 */
#define TCPOLEN_CC_NEW         6  /* page 17 of rfc1644 */
#define TCPOLEN_CC_ECHO        6  /* page 17 of rfc1644 */

#define TCPOPT_ALTCSUM          15  /* TCP Alternate Checksum Data [RFC1146], variable length */
#define TCPOPT_SKEETER          16  /* Skeeter [Knowles] */
#define TCPOPT_BUBBA            17  /* Bubba   [Knowles] */

#define TCPOPT_TRAILER_CSUM     18  /* Trailer Checksum Option [Subbu & Monroe] */
#define TCPOLEN_TRAILER_CSUM  3

#define TCPOPT_MD5SIG           19  /* MD5 Signature Option [RFC2385] */
#define TCPOLEN_MD5SIG        18

/* Space Communications Protocol Standardization */
#define TCPOPT_SCPS             20  /* Capabilities [Scott] */
#define TCPOPT_SELNEGACK        21  /* Selective Negative Acknowledgements [Scott] */
#define TCPOPT_RECORDBOUND         22  /* Record Boundaries [Scott] */
#define TCPOPT_CORRUPTION          23  /* Corruption experienced [Scott] */

#define TCPOPT_SNAP                24  /* SNAP [Sukonnik] -- anyone have info?*/
#define TCPOPT_UNASSIGNED          25  /* Unassigned (released 12/18/00) */
#define TCPOPT_COMPRESSION         26  /* TCP Compression Filter [Bellovin] */
/* http://www.research.att.com/~smb/papers/draft-bellovin-tcpcomp-00.txt*/

#define TCPOPT_AUTH   29  /* [RFC5925] - The TCP Authentication Option
                             Intended to replace MD5 Signature Option [RFC2385] */

#define TCP_HEADER_LEN tcp::hdr_len()

#endif /* TCP_H */
