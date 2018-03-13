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
// ip.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_IP_H
#define PROTOCOLS_IP_H

#include <cstring>

#include "main/snort_types.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "sfip/sf_ip.h"

namespace snort
{
struct Packet;

// FIXIT-L can I assume api is always valid?
// i.e. if not ip4, then ipv6?
// or if not ip4, also make sure its not ip6

namespace ip
{
// keeping this as a class to avoid confusion.
class SO_PUBLIC IpApi
{
public:
    enum Type { IAT_NONE, IAT_4, IAT_6, IAT_DATA };

    // constructor and destructor MUST remain a trivial. Adding
    // any non-trivial code will cause a compilation failure.
    IpApi() = default;

    void set(const IP4Hdr* h4);
    void set(const IP6Hdr* h6);
    void set(const SfIp& src, const SfIp& dst);
    bool set(const uint8_t* raw_ip_data);
    void update(const SfIp& sip, const SfIp& dip);
    void reset();

    // return the 16 bits associated with this IP layers frag_offset/flags
    uint16_t off_w_flags() const;
    // return the frag_offset associated with this IP layers in word size.
    //   (the value is internally masked and multiplied)
    uint16_t off() const;
    // return the frag_id associated with this IP layers
    uint32_t id() const;
    const uint8_t* ip_data() const; // return a pointer to the ip layers data

    // FIXIT-L get rid of the unnecessary ones
    // returns the sum of the ip header + payload lengths in host byte order
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
    { return (type != IAT_NONE); }

    inline bool is_ip6() const
    { return (type == IAT_6); }

    inline bool is_ip4() const
    { return (type == IAT_4); }

    inline bool is_ip() const
    { return is_ip4() or is_ip6(); }

    inline const IP4Hdr* get_ip4h() const
    { return (type == IAT_4) ? (const IP4Hdr*)iph : nullptr; }

    inline const IP6Hdr* get_ip6h() const
    { return (type == IAT_6) ? (const IP6Hdr*)iph : nullptr; }

    inline const SfIp* get_src() const
    { return (type != IAT_NONE) ? &src : nullptr; }

    inline const SfIp* get_dst() const
    { return (type != IAT_NONE) ? &dst : nullptr; }

    // only relevant to IP4
    inline uint8_t get_ip_opt_len() const
    { return (type == IAT_4) ? ((const IP4Hdr*)iph)->get_opt_len() : 0; }

    // only relevant to IP4
    inline const uint8_t* get_ip_opt_data() const
    { return (type == IAT_4) ? reinterpret_cast<const uint8_t*>(iph) + IP4_HEADER_LEN : nullptr; }

    inline const snort_in6_addr* get_ip6_src() const
    { return (type == IAT_6) ? ((const IP6Hdr*)iph)->get_src() : nullptr; }

    inline const snort_in6_addr* get_ip6_dst() const
    { return (type == IAT_6) ? ((const IP6Hdr*)iph)->get_dst() : nullptr; }

    uint16_t tos() const;
    uint8_t ttl() const;
    IpProtocol proto() const;
    uint16_t raw_len() const;
    uint8_t hlen() const;
    uint8_t ver() const;

private:
    SfIp src;
    SfIp dst;
    const void* iph;
    Type type;
};

} // namespace ip
} // namespace snort
#endif

