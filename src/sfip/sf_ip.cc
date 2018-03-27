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
// sf_ip.cc author Michael Altizer <mialtize@cisco.com>
// based on work by Adam Keeton

/* Library for managing IP addresses of either v6 or v4 families. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_ip.h"

#include <cassert>
#include <cmath> // For ceil

#include "main/thread.h"
#include "utils/util.h"
#include "utils/util_net.h"

#include "sf_cidr.h"

using namespace snort;

/* Support function */
// note that an ip6 address may have a trailing dotted quad form
// but that it always has at least 2 ':'s; furthermore there is
// no valid ip4 format (including mask) with 2 ':'s
// we don't have to figure out if the format is entirely legal
// we just have to be able to tell correct formats apart
static inline int sfip_str_to_fam(const char* str)
{
    const char* s;
    assert(str);
    s = strchr(str, (int)':');
    if ( s && strchr(s+1, (int)':') )
        return AF_INET6;
    if ( strchr(str, (int)'.') )
        return AF_INET;
    return AF_UNSPEC;
}

/* Masks off 'val' bits from the IP contained within 'ip' */
inline int SfIp::cidr_mask(int val)
{
    uint32_t* p;
    int index, bits;

    p = ip32;

    if (val < 0 || val > 128)
        return SFIP_ARG_ERR;

    if (val == 128)
        return SFIP_SUCCESS;

    /* Build the netmask by converting "val" into
     * the corresponding number of bits that are set */
    index = (int) ceil(val / 32.0) - 1;
    bits = 32 - (val - (index * 32));
    if (bits)
    {
        unsigned int mask;

        mask = ~0;
        mask >>= bits;
        mask <<= bits;
        p[index] &= htonl(mask);
    }

    index++;

    /* 0 off the rest of the IP */
    for (; index < 4; index++)
        p[index] = 0;

    return SFIP_SUCCESS;
}

/* Converts string IP format to an array of values. Also checks IP address format.
   Specifically look for issues that inet_pton either overlooks or is inconsistent
   about.  */
SfIpRet SfIp::pton(const int fam, const char* ip)
{
    const char* my_ip = ip;
    void* dst;

    if (!my_ip)
        return SFIP_FAILURE;

    /* Across platforms, inet_pton() is inconsistent about leading 0's in
       AF_INET (ie IPv4 addresses). */
    if (fam == AF_INET)
    {
        char chr;
        bool new_octet;

        new_octet = true;
        while ((chr = *my_ip++) != '\0')
        {
            /* If we are at the first char of a new octet, look for a leading zero
               followed by another digit */
            if (new_octet && (chr == '0') && isdigit(*my_ip))
                return SFIP_INET_PARSE_ERR;

            /* when we see an octet separator, set the flag to start looking for a
               leading zero. */
            new_octet = (chr == '.');
        }
        ip32[0] = ip32[1] = ip16[4] = 0;
        ip16[5] = 0xffff;
        dst = &ip32[3];
    }
    else
        dst = ip32;

    if (inet_pton(fam, ip, dst) < 1)
        return SFIP_INET_PARSE_ERR;

    family = fam;

    return SFIP_SUCCESS;  /* Otherwise, ip is OK */
}

/* Support function for _netmask_str_to_bit_count */
static inline int _count_bits(unsigned int val)
{
    unsigned int count;

    for (count = 0; val; count++)
    {
        val &= val - 1;
    }

    return count;
}

/* Support function for sfip_pton.  Used for converting a netmask string
 * into a number of bits to mask off */
static inline int _netmask_str_to_bit_count(char* mask, int family)
{
    uint32_t buf[4];
    int bits, i, nBits, nBytes;
    uint8_t* bytes = (uint8_t*)buf;

    /* XXX
     * Mask not validated.
     * Only sfip_pton should be using this function, and using it safely.
     * XXX */

    if (inet_pton(family, mask, buf) < 1)
        return -1;

    bits =  _count_bits(buf[0]);

    if (family == AF_INET6)
    {
        bits += _count_bits(buf[1]);
        bits += _count_bits(buf[2]);
        bits += _count_bits(buf[3]);
        nBytes = 16;
    }
    else
    {
        nBytes = 4;
    }

    // now make sure that only the most significant bits are set
    nBits = bits;
    for ( i = 0; i < nBytes; i++ )
    {
        if ( nBits >= 8 )
        {
            if ( bytes[i] != 0xff )
                return -1;
            nBits -= 8;
        }
        else if ( nBits == 0 )
        {
            if ( bytes[i] != 0x00 )
                return -1;
        }
        else
        {
            if ( bytes[i] != ((0xff00 >> nBits) & 0xff) )
                return -1;
            nBits = 0;
        }
    }
    return bits;
}

/* Parses "src" and stores results in "dst" */
SfIpRet SfIp::set(const char* src, uint16_t* srcBits)
{
    char* mask;
    char* sfip_buf;
    char* ip;
    int bits;

    if (!src)
        return SFIP_ARG_ERR;

    sfip_buf = snort_strdup(src);
    ip = sfip_buf;
    family = sfip_str_to_fam(src);

    /* skip whitespace or opening bracket */
    while (isspace((int)*ip) || (*ip == '['))
        ip++;

    /* check for and extract a mask in CIDR form */
    if ( (mask = strchr(ip, (int)'/')) != nullptr )
    {
        /* NULL out this character so inet_pton will see the
         * correct ending to the IP string */
        char* end = mask++;
        while ( (end > ip) && isspace((int)end[-1]) )
            end--;
        *end = 0;

        while (isspace((int)*mask))
            mask++;

        /* verify a leading digit */
        if (((family == AF_INET6) && !isxdigit((int)*mask)) ||
            ((family == AF_INET) && !isdigit((int)*mask)))
        {
            snort_free(sfip_buf);
            return SFIP_CIDR_ERR;
        }

        /* Check if there's a netmask here instead of the number of bits */
        if (strchr(mask, (int)'.') || strchr(mask, (int)':'))
            bits = _netmask_str_to_bit_count(mask, sfip_str_to_fam(mask));
        else
            bits = atoi(mask);
    }
    else if (
        /* If this is IPv4, ia ':' may used specified to indicate a netmask */
        ((family == AF_INET) && (mask = strchr(ip, (int)':')) != nullptr) ||

        /* We've already skipped the leading whitespace, if there is more
         * whitespace, then there's probably a netmask specified after it. */
        (mask = strchr(ip, (int)' ')) != nullptr
        )
    {
        char* end = mask++;
        while ( (end > ip) && isspace((int)end[-1]) )
            end--;
        *end = 0;  /* Now the IP will end at this point */

        /* skip whitespace */
        while (isspace((int)*mask))
            mask++;

        /* Make sure we're either looking at a valid digit, or a leading
         * colon, such as can be the case with IPv6 */
        if (((family == AF_INET) && isdigit((int)*mask)) ||
            ((family == AF_INET6) && (isxdigit((int)*mask) || *mask == ':')))
        {
            bits = _netmask_str_to_bit_count(mask, sfip_str_to_fam(mask));
        }
        /* No netmask */
        else
        {
            if (family == AF_INET)
                bits = 32;
            else
                bits = 128;
        }
    }
    /* No netmask */
    else
    {
        if (family == AF_INET)
            bits = 32;
        else
            bits = 128;
    }

    if (pton(family, ip) != SFIP_SUCCESS)
    {
        snort_free(sfip_buf);
        return SFIP_INET_PARSE_ERR;
    }

    /* Store mask */
    bits += (family == AF_INET && bits >= 0) ? 96 : 0;

    /* Apply mask */
    if (cidr_mask(bits) != SFIP_SUCCESS)
    {
        snort_free(sfip_buf);
        return SFIP_INVALID_MASK;
    }

    if (srcBits)
        *srcBits = bits;
    else if (bits != 128)
    {
        snort_free(sfip_buf);
        return SFIP_INET_PARSE_ERR;
    }

    snort_free(sfip_buf);
    return SFIP_SUCCESS;
}

SfIpRet SfIp::set(const void* src, int fam)
{
    assert(src);

    family = fam;
    if (family == AF_INET)
    {
        ip32[0] = ip32[1] = ip16[4] = 0;
        ip16[5] = 0xffff;
        ip32[3] = *(const uint32_t*)src;
    }
    else if (family == AF_INET6)
        memcpy(ip8, src, 16);
    else
        return SFIP_ARG_ERR;

    return SFIP_SUCCESS;
}

SfIpRet SfIp::set(const void* src)
{
    assert(src);
    if ( ((const uint32_t*)src)[0] == 0 &&
         ((const uint32_t*)src)[1] == 0 &&
         ((const uint16_t*)src)[4] == 0 &&
         ((const uint16_t*)src)[5] == 0xffff )
        return set(&((const uint32_t*)src)[3], AF_INET);
    return set(src, AF_INET6);
}

/* Obfuscates this IP with an obfuscation CIDR
    Makes this:  ob | (this & mask) */
void SfIp::obfuscate(SfCidr* ob)
{
    const uint32_t* ob_p;
    int index, i;
    unsigned int mask = 0;

    if (!ob)
        return;

    ob_p = ob->get_addr()->get_ip6_ptr();

    /* Build the netmask by converting "val" into
     * the corresponding number of bits that are set */
    index = (int)ceil(ob->get_bits() / 32.0) - 1;

    for (i = 0; i < 32 - (ob->get_bits() - (index * 32)); i++)
        mask = (mask << 1) + 1;

    /* Note: The old-Snort obfuscation code uses !mask for masking.
     * hence, this code uses the same algorithm as sfip_cidr_mask
     * except the mask below is not negated. */
    ip32[index] = htonl((ntohl(ip32[index]) & mask));

    /* 0 off the start of the IP */
    while ( index > 0 )
        ip32[--index] = 0;

    /* OR remaining pieces */
    ip32[0] |= ob_p[0];
    ip32[1] |= ob_p[1];
    ip32[2] |= ob_p[2];
    ip32[3] |= ob_p[3];
}

const char* SfIp::ntop(char* buf, int bufsize) const
{
    return snort_inet_ntop(family, get_ptr(), buf, bufsize);
}

const char* SfIp::ntop(SfIpString str) const
{
    return snort_inet_ntop(family, get_ptr(), str, sizeof(SfIpString));
}

bool SfIp::is_mapped() const
{
    if (ip32[0] || ip32[1] || ip16[4] || (ip16[5] != 0xffff && ip16[5]))
        return false;

    return true;
}

namespace snort
{
const char* snort_inet_ntop(int family, const void* ip_raw, char* buf, int bufsize)
{
    if (!ip_raw || !buf ||
        (family != AF_INET && family != AF_INET6) ||
        /* Make sure if it's IPv6 that the buf is large enough. */
        /* Need at least a max of 8 fields of 4 bytes plus 7 for colons in
         * between.  Need 1 more byte for null. */
        (family == AF_INET6 && bufsize < INET6_ADDRSTRLEN) ||
        /* Make sure if it's IPv4 that the buf is large enough.
           4 fields of 3 numbers, plus 3 dots and a null byte */
        (family == AF_INET && bufsize < INET_ADDRSTRLEN) )
    {
        if (buf && bufsize > 0)
            buf[0] = 0;
        return buf;
    }

#ifndef REG_TEST
    if (!inet_ntop(family, ip_raw, buf, bufsize))
        snprintf(buf, bufsize, "ERROR");
#else
    /* 4 fields of at most 3 characters each */
    if (family == AF_INET)
    {
        int i;
        const uint8_t* p = (const uint8_t*)ip_raw;

        for (i=0; p < ((const uint8_t*)ip_raw) + 4; p++)
        {
            i += sprintf(&buf[i], "%d", *p);

            /* If this is the last iteration, this could technically cause one
             *  extra byte to be written past the end. */
            if (i < bufsize && ((p + 1) < ((const uint8_t*)ip_raw+4)))
                buf[i] = '.';

            i++;
        }
    }
    else
    {
        int i;
        const uint16_t* p = (const uint16_t*)ip_raw;

        for (i=0; p < ((const uint16_t*)ip_raw) + 8; p++)
        {
            i += sprintf(&buf[i], "%04x", ntohs(*p));

            /* If this is the last iteration, this could technically cause one
             *  extra byte to be written past the end. */
            if (i < bufsize && ((p + 1) < ((const uint16_t*)ip_raw) + 8))
                buf[i] = ':';

            i++;
        }
    }
#endif
    return buf;
}

const char* sfip_ntop(const SfIp* ip, char* buf, int bufsize)
{
    if (!ip)
    {
        if (buf && bufsize > 0)
            buf[0] = 0;
    }
    else
        ip->ntop(buf, bufsize);

    return buf;
}
}
