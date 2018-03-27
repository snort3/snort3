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
// sf_cidr.h author Michael Altizer <mialtize@cisco.com>

#ifndef SF_CIDR_H
#define SF_CIDR_H

#include "sfip/sf_ip.h"

namespace snort
{
/*
 * NOTE: As much as I'd love to make this a subclass of SfIp, member layout
 * is undefined for POD inheritance.
 */

struct SO_PUBLIC SfCidr
{
    /*
     * Modifiers (incl. convenience ones that delegate to addr)
     */
    void clear();
    void set(const SfCidr& src);
    void set(const SfIp& src);
    SfIpRet set(const void* src, int fam);
    SfIpRet set(const char* src);
    void set_bits(uint16_t new_bits);

    /*
     * Accessors (incl. convenience ones that delegate to addr)
     */
    const SfIp* get_addr() const;
    uint16_t get_family() const;
    uint16_t get_bits() const;
    bool is_set() const;

    /*
     * Containment checks
     */
    bool fast_cont4(const SfIp& ip) const;
    bool fast_cont6(const SfIp& ip) const;
    SfIpRet contains(const SfIp* ip) const;

    const char* ntop(SfIpString) const;
    SfIpRet compare(const SfCidr&) const;

private:
    SfIp addr;
    uint16_t bits;
} __attribute__((__packed__));


inline void SfCidr::clear()
{
    addr.clear();
    bits = 0;
}

inline void SfCidr::set(const SfCidr& src)
{
    addr.set(src.addr);
    bits = src.bits;
}

inline void SfCidr::set(const SfIp& src)
{
    addr.set(src);
    bits = 128;
}

inline SfIpRet SfCidr::set(const void* src, int fam)
{
    SfIpRet ret = addr.set(src, fam);
    if (ret != SFIP_SUCCESS)
        return ret;
    bits = 128;
    return SFIP_SUCCESS;
}

inline void SfCidr::set_bits(uint16_t new_bits)
{
    if (new_bits > 128)
        return;
    bits = new_bits;
}

inline const SfIp* SfCidr::get_addr() const
{
    return &addr;
}

inline uint16_t SfCidr::get_family() const
{
    return addr.get_family();
}

inline uint16_t SfCidr::get_bits() const
{
    return bits;
}

inline bool SfCidr::is_set() const
{
    return (addr.is_set() ||
            ((addr.get_family() == AF_INET || addr.get_family() == AF_INET6) &&
             bits != 128));
}

inline bool SfCidr::fast_cont4(const SfIp& ip) const
{
    uint32_t shift = 128 - bits;
    uint32_t needle = ntohl(ip.get_ip4_value());
    uint32_t haystack = ntohl(addr.get_ip4_value());

    if (haystack == 0)
        return true;

    needle >>= shift;
    needle <<= shift;

    return haystack == needle;
}

inline bool SfCidr::fast_cont6(const SfIp& ip) const
{
    uint32_t needle;
    int words = bits / 32;
    int shift, i;

    for (i = 0; i < words; i++)
    {
        if (addr.get_ip6_ptr()[i] != ip.get_ip6_ptr()[i])
            return false;
    }

    shift = 32 - (bits % 32);
    if (shift == 32)
        return true;

    needle = ntohl(ip.get_ip6_ptr()[i]);

    needle >>= shift;
    needle <<= shift;

    return ntohl(addr.get_ip6_ptr()[i]) == needle;
}

inline const char* SfCidr::ntop(SfIpString ip_str) const
{
    return addr.ntop(ip_str);
}

inline SfIpRet SfCidr::compare(const SfCidr& cidr2) const
{
    SfIpRet ret = addr.compare(*cidr2.get_addr());
    if(SFIP_EQUAL == ret)
    {
        if(bits < cidr2.get_bits()) return SFIP_LESSER;
        if(bits > cidr2.get_bits()) return SFIP_GREATER;
    }
    return ret;
}
}
#endif
