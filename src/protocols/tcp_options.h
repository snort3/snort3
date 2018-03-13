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
// tcp_options.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_TCP_OPTIONS_H
#define PROTOCOLS_TCP_OPTIONS_H

#include "main/snort_types.h"

namespace snort
{
struct Packet;

namespace tcp
{
struct TCPHdr;

/* http://www.iana.org/assignments/tcp-parameters
 *
 * tcp options stuff. used to be in <netinet/tcp.h> but it breaks
 * things on AIX
 */

enum class TcpOptCode : std::uint8_t
{
    EOL = 0,    /* End of Option List [RFC793] */
    NOP = 1,    /* No-Option [RFC793] */
    MAXSEG = 2, /* Maximum Segment Size [RFC793] */
    WSCALE = 3, /* Window scaling option [RFC1323] */
    SACKOK = 4, /* Experimental [RFC2018]*/
    SACK = 5,   /* Experimental [RFC2018] variable length */
    ECHO = 6,   /* Echo (obsoleted by option 8)      [RFC1072] */
    ECHOREPLY = 7,  /* Echo Reply (obsoleted by option 8)[RFC1072] */
    TIMESTAMP = 8,  /* Timestamp [RFC1323], 10 bytes */
    PARTIAL_PERM = 9,   /* Partial Order Permitted/ Experimental [RFC1693] */
    PARTIAL_SVC = 10,   /*  Partial Order Profile [RFC1693] */
    CC = 11,        /*  T/TCP Connection count  [RFC1644] */
    CC_NEW = 12,    /*  CC.NEW [RFC1644] */
    CC_ECHO = 13,   /*  CC.ECHO [RFC1644] */

    ALTCSUM = 15,   /* TCP Alternate Checksum Data [RFC1146], variable length */
    SKEETER = 16,   /* Skeeter [Knowles] */
    BUBBA = 17,     /* Bubba   [Knowles] */
    TRAILER_CSUM = 18,  /* Trailer Checksum Option [Subbu & Monroe] */
    MD5SIG = 19,    /* MD5 Signature Option [RFC2385] */

    /* Space Communications Protocol Standardization */
    SCPS = 20,  /* Capabilities [Scott] */
    SELNEGACK = 21,     /* Selective Negative Acknowledgements [Scott] */
    RECORDBOUND = 22,   /* Record Boundaries [Scott] */
    CORRUPTION = 23,    /* Corruption experienced [Scott] */
    SNAP = 24,  /* SNAP [Sukonnik] -- anyone have info?*/
    UNASSIGNED = 25,    /* Unassigned (released 12/18/00) */
    COMPRESSION = 26,   /* TCP Compression Filter [Bellovin] */
    /* http://www.research.att.com/~smb/papers/draft-bellovin-tcpcomp-00.txt*/

    AUTH = 29,  /* [RFC5925] - The TCP Authentication Option
                             Intended to replace MD5 Signature Option [RFC2385] */
};

/*  Associated lengths */
const uint8_t TCPOLEN_EOL = 1;      /* Always one byte - [RFC793]*/
const uint8_t TCPOLEN_NOP = 1;      /* Always one byte - [RFC793]*/
const uint8_t TCPOLEN_MAXSEG = 4;   /* Always 4 bytes - [RFC793] */
const uint8_t TCPOLEN_WSCALE = 3;   /* 1 byte with logarithmic values - [RFC1323]*/
const uint8_t TCPOLEN_SACKOK = 2;   /* Experimental [RFC2018]*/
const uint8_t TCPOLEN_ECHO = 6;     /* 6 bytes  - Echo (obsoleted by option 8)      [RFC1072] */
const uint8_t TCPOLEN_ECHOREPLY = 6;    /* 6 bytes  - Echo Reply (obsoleted by option 8)[RFC1072]*/
const uint8_t TCPOLEN_TIMESTAMP = 10;   /* Timestamp [RFC1323], 10 bytes */
const uint8_t TCPOLEN_PARTIAL_PERM = 2; /* Partial Order Permitted/ Experimental [RFC1693] */
const uint8_t TCPOLEN_PARTIAL_SVC = 3;  /*  3 bytes long -- Experimental - [RFC1693] */

/* at least decode T/TCP options... */
const uint8_t TCPOLEN_CC = 6;       /* page 17 of rfc1644 */
const uint8_t TCPOLEN_CC_NEW = 6;   /* page 17 of rfc1644 */
const uint8_t TCPOLEN_CC_ECHO = 6;  /* page 17 of rfc1644 */

const uint8_t TCPOLEN_TRAILER_CSUM = 3;
const uint8_t TCPOLEN_MD5SIG = 18;

// FIXIT-L reduce all these classes to a simple pointer based approach
// that doesn't require any reinterpret casts (see also ipv4_options.h)
struct TcpOption
{
    TcpOptCode code;
    uint8_t len;
    uint8_t data[40];  // maximum possible

    inline uint8_t get_len() const
    { return ((uint8_t)code <= 1) ? 1 : len; }

    inline const uint8_t* get_data() const
    { return ((uint8_t)code <= 1 || len < 2) ? nullptr : &data[0]; }

    inline const TcpOption& next() const
    {
#ifdef __GNUC__
        const uint8_t tmp_len = ((uint8_t)code <= 1) ? 1 : len;
        const uint8_t* const tmp = reinterpret_cast<const uint8_t*>(this);
        const TcpOption* opt = reinterpret_cast<const TcpOption*>(&tmp[tmp_len]);
        return *opt;

#else
        if ( (uint8_t)code <= 1 )
            return reinterpret_cast<const TcpOption&>(len);
        else
            return reinterpret_cast<const TcpOption&>(data[len -2]);
#endif
    }
};

/*
 * Use TcpOptIterator ... this should NOT be called directly
 * unless you want to an actual iterator or some buggy code.
 */
class SO_PUBLIC TcpOptIteratorIter
{
public:
    TcpOptIteratorIter(const TcpOption*);

    bool operator==(const TcpOptIteratorIter& rhs)
    { return opt == rhs.opt; }

    bool operator!=(const TcpOptIteratorIter& rhs)
    { return opt != rhs.opt; }

    TcpOptIteratorIter& operator++()
    {
        opt = &opt->next();
        return *this;
    }

    const TcpOption& operator*() const;

private:
    const TcpOption* opt;
};

/*
 * Use IP ranged for loop rather than calling this directly.
 * i.e.,
 *      IpOptionIter iter(tcph, p)
 *      for (const TcpOption& opt : iter)
 *      {
 *          do_something
 *      }
 */
class SO_PUBLIC TcpOptIterator
{
public:
    /* CONSTRUCTOR VALID AFTER DECODE()
     * Some options in the provided header may not be valid.
     * Provide the packet struct ensures only valid options
     * will be returned
     */
    TcpOptIterator(const TCPHdr* const, const Packet* const);
    /* If you already know the validated option length (for instance,
     * if you are in a decode() method), then call this constructor.*/
    TcpOptIterator(const TCPHdr* const, const uint32_t valid_hdr_len);
    TcpOptIteratorIter begin() const;
    TcpOptIteratorIter end() const;

private:
    const uint8_t* start_ptr;
    const uint8_t* end_ptr;
};
} // namespace tcp
} // namespace snort

#endif

