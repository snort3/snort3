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

// ip.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_IP_H
#define PROTOCOLS_IP_H

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#else /* !WIN32 */
#include <netinet/in_systm.h>
#ifndef IFNAMSIZ
#define IFNAMESIZ MAX_ADAPTER_NAME
#endif /* !IFNAMSIZ */
#endif /* !WIN32 */

#include <cstring>

#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "sfip/sfip_t.h"
#include "main/snort_types.h"


struct Packet;

// FIXIT-J : can I assume api si always valid?  i.e. if not ip4, then ipv6?
//          or if not ip4, also make sure its not ip6

namespace ip
{

// keeping this as a class to avoid confusion.
class SO_PUBLIC IpApi
{
public:
//    IpApi();   constructor and destructor MUST remain a trivial. Adding
//    ~IpApi();  any non-trivial code will cause a compilation failure.
    IpApi() = default ;

    void set(const IP4Hdr* h4);
    void set(const IP6Hdr* h6);
    bool set(const uint8_t* raw_ip_data);
    void reset();
    // return the 16 bits associated with this IP layers frag_offset/flags
    uint16_t off_w_flags() const;
    // return the frag_offset associated with this IP layers in word size.
    //   (the value is internally masked and multiplied)
    uint16_t off() const;
    // return the frag_id associated with this IP layers
    uint32_t id() const;
    const uint8_t* ip_data() const; // return a pointer to the ip layers data

    // FIXIT-L J get rid of the unnecessary ones
    // returns the length of the ip header + length in host byte order
    uint16_t dgram_len() const;
    // returns this ip layer's payload length in host byte order
    uint16_t pay_len() const;
    // return the ip_len field in host byte order
    uint16_t actual_ip_len() const;
    // true if the current source address ia the loopback address
    bool is_src_loopback() const;
    // true if the current source address ia the loopback address
    bool is_dst_loopback() const;
    // overloaded == operators.
    friend bool operator==(const IpApi& lhs, const IpApi& rhs);
    friend bool operator!=(const IpApi& lhs, const IpApi& rhs);


    // returns true if this api is set.
    inline bool is_valid() const
    { return (ip4h || ip6h); }

    inline bool is_ip6() const
    { return ip6h; }

    inline bool is_ip4() const
    { return ip4h; }

    inline const IP4Hdr* get_ip4h() const
    { return ip4h; }

    inline const IP6Hdr* get_ip6h() const
    { return ip6h; }

    inline const sfip_t *get_src() const
    { return src_p; }

    inline const sfip_t *get_dst() const
    { return dst_p; }

    inline uint16_t tos() const
    { return ip4h ? ip4h->tos() : ip6h ? ip6h->tos() : 0; }

    inline uint8_t ttl() const
    { return ip4h ? ip4h->ttl() : ip6h ? ip6h->hop_lim() : 0; }

    /* This is different than the Packet's ip_proto_next field - this
     * variable hold the first non-ip and non-ipv6 extension protocols,
     * while proto() returns the next or proto() field of the raw IP
     * header */
    inline uint8_t proto() const
    { return ip4h ? ip4h->proto() : ip6h ? ip6h->next() : 0xFF; }

    // NOTE:  ipv4 len contains header, ipv6 header does not. If you
    //        want a standard, use dgram_len() or pay_len() instead.
//    inline uint16_t len() const
//    { return ip4h ? ip4h->len() : ip6h ? ip6h->len() : 0; }

    inline uint16_t raw_len() const
    { return ip4h ? ip4h->raw_len() : ip6h ? ip6h->raw_len() : 0; }

    inline uint8_t hlen() const
    { return ip4h ? ip4h->hlen() : ip6h ? ip6h->hlen() : 0; }

    inline uint8_t ver() const
    { return ip4h ? ip4h->ver() : ip6h ? ip6h->ver() : 0; }


    // only relevent to IP4.
    inline uint8_t get_ip_opt_len() const
    { return ip4h ? ip4h->get_opt_len() : 0; }

    // only relevent to IP4.
    inline const uint8_t* get_ip_opt_data() const
    { return ip4h ? reinterpret_cast<const uint8_t*>(ip4h + IP4_HEADER_LEN) : nullptr; }

    inline const snort_in6_addr* get_ip6_src() const
    { return ip6h ? ip6h->get_src() : nullptr; }

    inline const snort_in6_addr* get_ip6_dst() const
    { return ip6h ? ip6h->get_dst() : nullptr; }

private:
    sfip_t src;
    sfip_t dst;
    const sfip_t *src_p;
    const sfip_t *dst_p;
    const IP4Hdr* ip4h;
    const IP6Hdr* ip6h;
};


inline bool operator==(const IpApi& lhs, const IpApi& rhs)
{ return (lhs.ip4h == rhs.ip4h) && (lhs.ip6h == rhs.ip6h); }

inline bool operator!=(const IpApi& lhs, const IpApi& rhs)
{ return !(lhs == rhs); }


} // namespace ip

#endif
