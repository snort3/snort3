//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

/*
 * Adam Keeton
 * sf_ip.c
 * 11/17/06
 *
 * Library for managing IP addresses of either v6 or v4 families.
*/

#include "sf_ip.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h> /* For ceil */

/* For inet_pton */
#include <sys/types.h>
#include <arpa/inet.h>

#include "main/thread.h"
#include "protocols/ipv6.h"
#include "utils/util.h"

#if 0
/* Support function .. but could see some external uses */
static inline int sfip_length(sfip_t* ip)
{
    ARG_CHECK1(ip, 0);

    if (sfip_family(ip) == AF_INET)
        return 4;
    return 16;
}

#endif

/* Support function */
// note that an ip6 address may have a trailing dotted quad form
// but that it always has at least 2 ':'s; furthermore there is
// no valid ip4 format (including mask) with 2 ':'s
// we don't have to figure out if the format is entirely legal
// we just have to be able to tell correct formats apart
static inline int sfip_str_to_fam(const char* str)
{
    const char* s;
    ARG_CHECK1(str, 0);
    s = strchr(str, (int)':');
    if ( s && strchr(s+1, (int)':') )
        return AF_INET6;
    if ( strchr(str, (int)'.') )
        return AF_INET;
    return AF_UNSPEC;
}

/* Place-holder allocation incase we want to do something more indepth later */
static inline sfip_t* _sfip_alloc()
{
    return (sfip_t*)snort_calloc(sizeof(sfip_t));
}

/* Masks off 'val' bits from the IP contained within 'ip' */
static inline int sfip_cidr_mask(sfip_t* ip, int val)
{
    int i;
    unsigned int mask = 0;
    unsigned int* p;
    int index = (int)ceil(val / 32.0) - 1;

    ARG_CHECK1(ip, SFIP_ARG_ERR);

    p = ip->ip32;

    if ( val < 0 ||
        ((sfip_family(ip) == AF_INET6) && val > 128) ||
        ((sfip_family(ip) == AF_INET) && val > 32) )
    {
        return SFIP_ARG_ERR;
    }

    /* Build the netmask by converting "val" into
     * the corresponding number of bits that are set */
    for (i = 0; i < 32- (val - (index * 32)); i++)
        mask = (mask<<1) + 1;

    p[index] = htonl((ntohl(p[index]) & ~mask));

    index++;

    /* 0 off the rest of the IP */
    for (; index<4; index++)
        p[index] = 0;

    return SFIP_SUCCESS;
}

/* Converts string IP format to an array of values. Also checks IP address format.
   Specifically look for issues that inet_pton either overlooks or is inconsistent
   about.  */
static inline SFIP_RET sfip_convert_ip_text_to_binary(const int family, const char* ip, void* dst)
{
    const char* my_ip = ip;

    if ( my_ip == NULL )
        return( SFIP_FAILURE );

    /* Across platforms, inet_pton() is inconsistent about leading 0's in
       AF_INET (ie IPv4 addresses. */
    if ( family == AF_INET )
    {
        char chr;
        bool new_octet;

        new_octet = true;
        while ( (chr = *my_ip++) != '\0')
        {
            /* If we are at the first char of a new octet, look for a leading zero
               followed by another digit */
            if ( new_octet && (chr == '0') && isdigit(*my_ip))
                return( SFIP_INET_PARSE_ERR );

            /* when we see an octet separator, set the flag to start looking for a
               leading zero. */
            new_octet = (chr == '.');
        }
    }

    if ( inet_pton(family, ip, dst) < 1 )
        return( SFIP_INET_PARSE_ERR );

    return( SFIP_SUCCESS );  /* Otherwise, ip is OK */
}

/* Allocate IP address from a character array describing the IP */
sfip_t* sfip_alloc(const char* ip, SFIP_RET* status)
{
    SFIP_RET tmp;
    sfip_t* ret;

    if (!ip)
    {
        if (status)
            *status = SFIP_ARG_ERR;
        return NULL;
    }

    if ((ret = _sfip_alloc()) == NULL)
    {
        if (status)
            *status = SFIP_ALLOC_ERR;
        return NULL;
    }

    if ( (tmp = sfip_pton(ip, ret)) != SFIP_SUCCESS)
    {
        if (status)
            *status = tmp;

        sfip_free(ret);
        return NULL;
    }

    if (status)
        *status = SFIP_SUCCESS;

    return ret;
}

/* Allocate IP address from an array of 8 byte integers */
sfip_t* sfip_alloc_raw(void* ip, int family, SFIP_RET* status)
{
    sfip_t* ret;

    if (!ip)
    {
        if (status)
            *status = SFIP_ARG_ERR;
        return NULL;
    }

    if ((ret = _sfip_alloc()) == NULL)
    {
        if (status)
            *status = SFIP_ALLOC_ERR;
        return NULL;
    }

    ret->bits = (family==AF_INET ? 32 : 128);
    ret->family = family;
    /* XXX Replace with appropriate "high speed" copy */
    memcpy(ret->ip8, ip, ret->bits/8);

    if (status)
        *status = SFIP_SUCCESS;

    return ret;
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
SFIP_RET sfip_pton(const char* src, sfip_t* dst)
{
    char* mask;
    char* sfip_buf;
    char* ip;
    int bits;

    if (!dst || !src)
        return SFIP_ARG_ERR;

    sfip_buf = snort_strdup(src);
    ip = sfip_buf;
    dst->family = sfip_str_to_fam(src);

    /* skip whitespace or opening bracket */
    while (isspace((int)*ip) || (*ip == '['))
        ip++;

    /* check for and extract a mask in CIDR form */
    if ( (mask = strchr(ip, (int)'/')) != NULL )
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
        if (((dst->family == AF_INET6) && !isxdigit((int)*mask)) ||
            ((dst->family == AF_INET) && !isdigit((int)*mask)))
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
        ((dst->family == AF_INET) && (mask = strchr(ip, (int)':')) != NULL) ||

        /* We've already skipped the leading whitespace, if there is more
         * whitespace, then there's probably a netmask specified after it. */
        (mask = strchr(ip, (int)' ')) != NULL
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
        if (((dst->family == AF_INET) && isdigit((int)*mask)) ||
            ((dst->family == AF_INET6) && (isxdigit((int)*mask) || *mask == ':')))
        {
            bits = _netmask_str_to_bit_count(mask, sfip_str_to_fam(mask));
        }
        /* No netmask */
        else
        {
            if (dst->family == AF_INET)
                bits = 32;
            else
                bits = 128;
        }
    }
    /* No netmask */
    else
    {
        if (dst->family == AF_INET)
            bits = 32;
        else
            bits = 128;
    }

    if (sfip_convert_ip_text_to_binary(dst->family, ip, dst->ip8) != SFIP_SUCCESS)
    {
        snort_free(sfip_buf);
        return SFIP_INET_PARSE_ERR;
    }

    /* Store mask */
    dst->bits = bits;

    /* Apply mask */
    if (sfip_cidr_mask(dst, bits) != SFIP_SUCCESS)
    {
        snort_free(sfip_buf);
        return SFIP_INVALID_MASK;
    }

    snort_free(sfip_buf);
    return SFIP_SUCCESS;
}

/* Sets existing IP, "dst", to be source IP, "src" */
SFIP_RET sfip_set_raw(sfip_t* dst, const void* src, int family)
{
    ARG_CHECK3(dst, src, dst->ip32, SFIP_ARG_ERR);

    dst->family = family;

    if (family == AF_INET)
    {
        dst->ip32[0] = *(uint32_t*)src;
        memset(&dst->ip32[1], 0, 12);
        dst->bits = 32;
    }
    else if (family == AF_INET6)
    {
        memcpy(dst->ip8, src, 16);
        dst->bits = 128;
    }
    else
    {
        return SFIP_ARG_ERR;
    }

    return SFIP_SUCCESS;
}

/* Sets existing IP, "dst", to be source IP, "src" */
SFIP_RET sfip_set_ip(sfip_t* dst, const sfip_t* src)
{
    ARG_CHECK2(dst, src, SFIP_ARG_ERR);

    dst->family = src->family;
    dst->bits = src->bits;
    dst->ip32[0] = src->ip32[0];
    dst->ip32[1] = src->ip32[1];
    dst->ip32[2] = src->ip32[2];
    dst->ip32[3] = src->ip32[3];

    return SFIP_SUCCESS;
}

/* Obfuscates an IP
 * Makes 'ip': ob | (ip & mask) */
void sfip_obfuscate(sfip_t* ob, sfip_t* ip)
{
    unsigned int* ob_p, * ip_p;
    int index, i;
    unsigned int mask = 0;

    if (!ob || !ip)
        return;

    ob_p = ob->ip32;
    ip_p = ip->ip32;

    /* Build the netmask by converting "val" into
     * the corresponding number of bits that are set */
    index = (int)ceil(ob->bits / 32.0) - 1;

    for (i = 0; i < 32- (ob->bits - (index * 32)); i++)
        mask = (mask<<1) + 1;

    /* Note: The old-Snort obfuscation code uses !mask for masking.
     * hence, this code uses the same algorithm as sfip_cidr_mask
     * except the mask below is not negated. */
    ip_p[index] = htonl((ntohl(ip_p[index]) & mask));

    /* 0 off the start of the IP */
    while ( index > 0 )
        ip_p[--index] = 0;

    /* OR remaining pieces */
    ip_p[0] |= ob_p[0];
    ip_p[1] |= ob_p[1];
    ip_p[2] |= ob_p[2];
    ip_p[3] |= ob_p[3];
}

/* Check if ip is contained within the network specified by net */
/* Returns SFIP_EQUAL if so.
 * XXX sfip_contains assumes that "ip" is
 *      not less-specific than "net" XXX
*/
SFIP_RET sfip_contains(const sfip_t* net, const sfip_t* ip)
{
    unsigned int bits, mask, temp, i;
    int net_fam, ip_fam;
    const unsigned int* p1, * p2;

    /* SFIP_CONTAINS is returned here due to how sfvar_ip_in
     * handles zero'ed IPs" */
    ARG_CHECK2(net, ip, SFIP_CONTAINS);

    bits = sfip_bits(net);
    net_fam = sfip_family(net);
    ip_fam = sfip_family(ip);

    /* If the families are mismatched, check if we're really comparing
     * an IPv4 with a mapped IPv4 (in IPv6) address. */
    if (net_fam != ip_fam)
    {
        if ((net_fam != AF_INET) || !sfip_ismapped(ip))
            return SFIP_ARG_ERR;

        /* Both are really IPv4.  Only compare last 4 bytes of 'ip'*/
        p1 = net->ip32;
        p2 = &ip->ip32[3];

        /* Mask off bits */
        bits = 32 - bits;
        temp = (ntohl(*p2) >> bits) << bits;

        if (ntohl(*p1) == temp)
            return SFIP_CONTAINS;

        return SFIP_NOT_CONTAINS;
    }

    p1 = net->ip32;
    p2 = ip->ip32;

    /* Iterate over each 32 bit segment */
    for (i=0; i < bits/32 && i < 3; i++, p1++, p2++)
    {
        if (*p1 != *p2)
            return SFIP_NOT_CONTAINS;
    }

    mask = 32 - (bits - 32*i);
    if ( mask == 32 )
        return SFIP_CONTAINS;

    /* At this point, there are some number of remaining bits to check.
     * Mask the bits we don't care about off of "ip" so we can compare
     * the ints directly */
    temp = ntohl(*p2);
    temp = (temp >> mask) << mask;

    /* If p1 was setup correctly through this library, there is no need to
     * mask off any bits of its own. */
    if (ntohl(*p1) == temp)
        return SFIP_CONTAINS;

    return SFIP_NOT_CONTAINS;
}

void sfip_raw_ntop(int family, const void* ip_raw, char* buf, int bufsize)
{
    if (!ip_raw || !buf ||
        (family != AF_INET && family != AF_INET6) ||
        /* Make sure if it's IPv6 that the buf is large enough. */
        /* Need atleast a max of 8 fields of 4 bytes plus 7 for colons in
         * between.  Need 1 more byte for null. */
        (family == AF_INET6 && bufsize < INET6_ADDRSTRLEN) ||
        /* Make sure if it's IPv4 that the buf is large enough.
           4 fields of 3 numbers, plus 3 dots and a null byte */
        (family == AF_INET && bufsize < INET_ADDRSTRLEN) )
    {
        if (buf && bufsize > 0)
            buf[0] = 0;
        return;
    }

#if defined(HAVE_INET_NTOP) && !defined(REG_TEST)
    if (!inet_ntop(family, ip_raw, buf, bufsize))
        snprintf(buf, bufsize, "ERROR");
#else
    /* 4 fields of at most 3 characters each */
    if (family == AF_INET)
    {
        int i;
        uint8_t* p = (uint8_t*)ip_raw;

        for (i=0; p < ((uint8_t*)ip_raw) + 4; p++)
        {
            i += sprintf(&buf[i], "%d", *p);

            /* If this is the last iteration, this could technically cause one
             *  extra byte to be written past the end. */
            if (i < bufsize && ((p + 1) < ((uint8_t*)ip_raw+4)))
                buf[i] = '.';

            i++;
        }

        /* Check if this is really just an IPv4 address represented as 6,
         * in compatible format */
#if 0
    }
    else if (!field[0] && !field[1] && !field[2])
    {
        unsigned char* p = (unsigned char*)(&ip->ip[12]);

        for (i=0; p < &ip->ip[16]; p++)
            i += sprintf(&buf[i], "%d.", *p);
#endif
    }
    else
    {
        int i;
        uint16_t* p = (uint16_t*)ip_raw;

        for (i=0; p < ((uint16_t*)ip_raw) + 8; p++)
        {
            i += sprintf(&buf[i], "%04x", ntohs(*p));

            /* If this is the last iteration, this could technically cause one
             *  extra byte to be written past the end. */
            if (i < bufsize && ((p + 1) < ((uint16_t*)ip_raw) + 8))
                buf[i] = ':';

            i++;
        }
    }
#endif
}

void sfip_ntop(const sfip_t* ip, char* buf, int bufsize)
{
    if (!ip)
    {
        if (buf && bufsize > 0)
            buf[0] = 0;
        return;
    }

    sfip_raw_ntop(sfip_family(ip), ip->ip32, buf, bufsize);
}

/* Uses a static buffer to return a string representation of the IP */
char* sfip_to_str(const sfip_t* ip)
{
    static THREAD_LOCAL char buf[INET6_ADDRSTRLEN];

    sfip_ntop(ip, buf, sizeof(buf));

    return buf;
}

void sfip_free(sfip_t* ip)
{
    if (ip)
        snort_free(ip);
}

int sfip_ismapped(const sfip_t* ip)
{
    const unsigned int* p;

    ARG_CHECK1(ip, 0);

    if (sfip_family(ip) == AF_INET)
        return 0;

    p = ip->ip32;

    if (p[0] || p[1] || (ntohl(p[2]) != 0xffff && p[2] != 0))
        return 0;

    return 1;
}

#ifdef UNIT_TEST
// FIXIT-L this is a hack to get catch to run these tests
// otherwise the linker omits the auto registration foo
// and the tests will not run
#include "sfip_test.cc"
#endif

