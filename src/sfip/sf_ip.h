//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
// sf_ip.h author Michael Altizer <mialtize@cisco.com>
// based on work by Adam Keeton

#ifndef SF_IP_H
#define SF_IP_H

#include <arpa/inet.h>
#include <sys/socket.h>

#include <sstream>

#include "main/snort_types.h"
#include "sfip/sf_returns.h"

namespace snort
{
struct SfCidr;

struct SO_PUBLIC SfIp
{
    /*
     * Constructors
     */
    SfIp() = default;
    SfIp(const void* src, int fam) { set(src, fam); }

    /*
     * Modifiers
     */
    void clear();
    void set(const SfIp& src);
    SfIpRet set(const char* src, uint16_t* srcBits = nullptr);
    /* Sets to a raw source IP (4 or 16 bytes, according to family) */
    SfIpRet set(const void* src, int fam);
    /* Converts string IP format to an array of values. Also checks IP address format. */
    SfIpRet pton(const int fam, const char* ip);

    /*
     * Accessors
     */
    uint16_t get_family() const;
    uint32_t get_ip4_value() const;
    const uint32_t* get_ip4_ptr() const;
    const uint32_t* get_ip6_ptr() const;
    const uint32_t* get_ptr() const;
    bool is_set() const;
    bool is_ip6() const;
    bool is_ip4() const;

    /*
     *  Comparison functions
     */
    bool equals(const SfIp& rhs, bool match_unset = true) const;
    bool less_than(const SfIp& rhs) const;
    bool greater_than(const SfIp& rhs) const;
    SfIpRet compare(const SfIp& ip2, bool match_unset = true) const;
    bool fast_eq4(const SfIp& ip2) const;
    bool fast_lt6(const SfIp& ip2) const;
    bool fast_gt6(const SfIp& ip2) const;
    bool fast_eq6(const SfIp& ip2) const;
    bool fast_equals_raw(const SfIp& ip2) const;

    /*
     * Miscellaneous
     */
    /* Returns true if the IPv6 address appears mapped. */
    bool is_mapped() const;
    bool is_loopback() const;
    bool is_private() const;

    const char* ntop(char* buf, int bufsize) const;
    const char* ntoa() const;

    void obfuscate(SfCidr* ob);

private:
    int cidr_mask(int val);
    bool _is_equals(const SfIp& rhs) const;
    bool _is_lesser(const SfIp& rhs) const;
    SfIpRet _ip6_cmp(const SfIp& ip2) const;

    union
    {
        uint8_t ip8[16];
        uint16_t ip16[8];
        uint32_t ip32[4];
    };
    int16_t family;
} __attribute__((__packed__));


/*
 * Member function definitions
 */

inline void SfIp::clear()
{
    family = 0;
    ip32[0] = ip32[1] = ip32[2] = ip32[3] = 0;
}

inline void SfIp::set(const SfIp& src)
{
    /* This is a simple structure, so is this really better than
     *this = src?. */
    family = src.family;
    ip32[0] = src.ip32[0];
    ip32[1] = src.ip32[1];
    ip32[2] = src.ip32[2];
    ip32[3] = src.ip32[3];
}

inline uint16_t SfIp::get_family() const
{
    return family;
}

inline uint32_t SfIp::get_ip4_value() const
{
    return ip32[3];
}

inline const uint32_t* SfIp::get_ip4_ptr() const
{
    return &ip32[3];
}

inline const uint32_t* SfIp::get_ip6_ptr() const
{
    return ip32;
}

inline const uint32_t* SfIp::get_ptr() const
{
    if (is_ip4())
        return &ip32[3];
    return ip32;
}

inline bool SfIp::is_set() const
{
    return ((family == AF_INET && ip32[3]) ||
            (family == AF_INET6 &&
             (ip32[0] || ip32[1] || ip32[3] || ip16[4] ||
              (ip16[5] && ip16[5] != 0xffff))));
}

inline bool SfIp::is_ip6() const
{
    return family == AF_INET6;
}

inline bool SfIp::is_ip4() const
{
    return family == AF_INET;
}

inline bool SfIp::is_loopback() const
{
    /* Check the first 80 bits in an IPv6 address, and
        verify they're zero.  If not, it's not a loopback */
    if (ip32[0] || ip32[1] || ip16[4])
        return false;

    if (ip16[5] == 0xffff)
    {
        /* ::ffff:127.0.0.0/104 is IPv4 loopback mapped over IPv6 */
        return (ip8[12] == 0x7f);
    }

    if (!ip16[5])
    {
        /* ::7f00:0/104 is ipv4 compatible ipv6
           ::1 is the IPv6 loopback */
        return (ip32[3] == htonl(0x1) || ip8[12] == 0x7f);
    }

    return false;
}

inline bool SfIp::is_private() const
{
    /* Check the first 80 bits in an IPv6 address, and
        verify they're zero.  If not, it's not a loopback. */
    if (ip32[0] || ip32[1] || ip16[4])
        return false;

    /* (Mapped) v4 private addresses */
    if (ip16[5] == 0xffff)
    {
        /*
         * 10.0.0.0        -   10.255.255.255  (10/8 prefix)
         * 172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
         * 192.168.0.0     -   192.168.255.255 (192.168/16 prefix)
         */
        return ( (ip8[12] == 10)
               || ((ip8[12] == 172) && ((ip8[13] & 0xf0) == 16))
               || ((ip8[12] == 192) && (ip8[13] == 168)) );
    }

    /* Check if the 3rd 32-bit int is zero */
    if (!ip16[5])
    {
        /* ::ipv4 compatible ipv6
           ::1 is the IPv6 loopback */
        return ( (ip8[12] == 10)
               || ((ip8[12] == 172) && ((ip8[13] & 0xf0) == 16))
               || ((ip8[12] == 192) && (ip8[13] == 168))
               || (ip32[3] == htonl(0x1)) );
    }

    return false;
}

inline bool SfIp::_is_equals(const SfIp& rhs) const
{
    if (is_ip4())
    {
        return (rhs.is_ip4()) &&
               (ip32[3] == rhs.ip32[3]);
    }
    else if (is_ip6())
    {
        return (rhs.is_ip6()) &&
               (ip32[0] == rhs.ip32[0]) &&
               (ip32[1] == rhs.ip32[1]) &&
               (ip32[2] == rhs.ip32[2]) &&
               (ip32[3] == rhs.ip32[3]);
    }
    return false;
}

inline bool SfIp::_is_lesser(const SfIp& rhs) const
{
    if (is_ip4())
    {
        return (rhs.is_ip4() &&
               (htonl(ip32[3]) < htonl(rhs.ip32[3])));
    }
    else if (is_ip6())
    {
        return (rhs.is_ip6() &&
               (htonl(ip32[0]) < htonl(rhs.ip32[0])) &&
               (htonl(ip32[1]) < htonl(rhs.ip32[1])) &&
               (htonl(ip32[2]) < htonl(rhs.ip32[2])) &&
               (htonl(ip32[3]) < htonl(rhs.ip32[3])));
    }
    return false;
}

inline bool SfIp::equals(const SfIp& rhs, bool match_unset) const
{
    if (!is_set() || !rhs.is_set())
        return match_unset;

    return _is_equals(rhs);
}

inline bool SfIp::less_than(const SfIp& rhs) const
{
    // I'm copying and pasting.  Don't ask me why this is different then sfip_equals
    if (!is_set() || !rhs.is_set())
        return false;

    return _is_lesser(rhs);
}

inline bool SfIp::greater_than(const SfIp& rhs) const
{
    // I'm copying and pasting.  Don't ask me why this is different then sfip_equals
    if (!is_set() || !rhs.is_set())
        return false;

    return rhs._is_lesser(*this);
}

/* Support function for SfIp::compare() */
inline SfIpRet _ip4_cmp(uint32_t ip1, uint32_t ip2)
{
    uint32_t hip1 = htonl(ip1);
    uint32_t hip2 = htonl(ip2);
    if (hip1 < hip2)
        return SFIP_LESSER;
    if (hip1 > hip2)
        return SFIP_GREATER;
    return SFIP_EQUAL;
}

/* Support function for SfIp::compare() */
inline SfIpRet SfIp::_ip6_cmp(const SfIp& ip2) const
{
    SfIpRet ret;
    const uint32_t* p1, * p2;

    p1 = ip32;
    p2 = ip2.ip32;

    if ( (ret = _ip4_cmp(p1[0], p2[0])) != SFIP_EQUAL)
        return ret;
    if ( (ret = _ip4_cmp(p1[1], p2[1])) != SFIP_EQUAL)
        return ret;
    if ( (ret = _ip4_cmp(p1[2], p2[2])) != SFIP_EQUAL)
        return ret;
    if ( (ret = _ip4_cmp(p1[3], p2[3])) != SFIP_EQUAL)
        return ret;

    return ret;
}

/*
 * Returns SFIP_LESSER, SFIP_EQUAL, SFIP_GREATER, if this is less than, equal to,
 * or greater than ip2.  In the case of mismatched families, the IPv4 address
 * is converted to an IPv6 representation.
 * To support existing Snort code, an unset IP is considered to match anything
 * unless 'match_unset' is set to false.
 */
inline SfIpRet SfIp::compare(const SfIp& ip2, bool match_unset) const
{
    if (!is_set() || !ip2.is_set())
    {
        if (match_unset)
            return SFIP_EQUAL;
        return SFIP_FAILURE;
    }

    if (is_ip4() && ip2.is_ip4())
        return _ip4_cmp(get_ip4_value(), ip2.get_ip4_value());

    return _ip6_cmp(ip2);
}

inline bool SfIp::fast_eq4(const SfIp& ip2) const
{
    return get_ip4_value() == ip2.get_ip4_value();
}

inline bool SfIp::fast_lt6(const SfIp& ip2) const
{
    const uint32_t* p1, * p2;

    p1 = ip32;
    p2 = ip2.ip32;

    if (*p1 < *p2)
        return true;
    else if (*p1 > *p2)
        return false;

    if (p1[1] < p2[1])
        return true;
    else if (p1[1] > p2[1])
        return false;

    if (p1[2] < p2[2])
        return true;
    else if (p1[2] > p2[2])
        return false;

    if (p1[3] < p2[3])
        return true;
    else if (p1[3] > p2[3])
        return false;

    return false;
}

inline bool SfIp::fast_gt6(const SfIp& ip2) const
{
    const uint32_t* p1, * p2;

    p1 = ip32;
    p2 = ip2.ip32;

    if (*p1 > *p2)
        return true;
    else if (*p1 < *p2)
        return false;

    if (p1[1] > p2[1])
        return true;
    else if (p1[1] < p2[1])
        return false;

    if (p1[2] > p2[2])
        return true;
    else if (p1[2] < p2[2])
        return false;

    if (p1[3] > p2[3])
        return true;
    else if (p1[3] < p2[3])
        return false;

    return false;
}

inline bool SfIp::fast_eq6(const SfIp& ip2) const
{
    const uint32_t* p1, * p2;

    p1 = ip32;
    p2 = ip2.ip32;

    if (*p1 != *p2)
        return false;
    if (p1[1] != p2[1])
        return false;
    if (p1[2] != p2[2])
        return false;
    if (p1[3] != p2[3])
        return false;

    return true;
}

inline bool SfIp::fast_equals_raw(const SfIp& ip2) const
{
    int f1,f2;

    f1 = family;
    f2 = ip2.family;

    if (f1 == AF_INET)
    {
        if (f2 != AF_INET)
            return false;
        if (fast_eq4(ip2))
            return true;
    }
    else if (f1 == AF_INET6)
    {
        if (f2 != AF_INET6)
            return false;
        if (fast_eq6(ip2))
            return true;
    }
    return false;
}

/* End of member function definitions */

SO_PUBLIC const char* sfip_ntop(const SfIp* ip, char* buf, int bufsize);

inline std::ostream& operator<<(std::ostream& os, const SfIp* addr)
{
    char str[INET6_ADDRSTRLEN];
    sfip_ntop(addr, str, sizeof(str));
    os << str;
    return os;
}

// FIXIT-L X This should be in utils_net if anywhere, but that makes it way harder to link into unit tests
SO_PUBLIC const char* snort_inet_ntop(int family, const void* ip_raw, char* buf, int bufsize);
}
#endif

