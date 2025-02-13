//--------------------------------------------------------------------------
// Copyright (C) 2018-2025 Cisco and/or its affiliates. All rights reserved.
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

// endian.h author Carter Waxman <cwaxman@cisco.com>

// Different POSIX systems handle 64-bit endian swaps in different ways. This
// header creates a standard interface to use throughout Snort, htonll(value).

#ifndef SNORT_ENDIAN_H
#define SNORT_ENDIAN_H

# include <netinet/in.h>

#ifdef __FreeBSD__
# include <sys/endian.h>
# define bswap_16(a) bswap16(a)
# define bswap_32(a) bswap32(a)
# define bswap_64(a) bswap64(a)
#endif

#ifdef __linux__
# include <byteswap.h>
#endif

#ifndef __APPLE__
# define htonll(a) ( 1 == htonl(1) ? (a) : bswap_64(a) )
# define ntohll(a) ( 1 == ntohl(1) ? (a) : bswap_64(a) )
#endif

#if defined(WORDS_BIGENDIAN)
#define LETOHS(p)   bswap_16(*((const uint16_t*)(p)))
#define LETOHL(p)   bswap_32(*((const uint32_t*)(p)))
#else
#define LETOHS(p)   (*((const uint16_t*)(p)))
#define LETOHL(p)   (*((const uint32_t*)(p)))
#endif

#define LETOHS_UNALIGNED(p) \
    ((uint16_t)(*((const uint8_t*)(p) + 1) << 8) | \
     (uint16_t)(*((const uint8_t*)(p))))

#define LETOHL_UNALIGNED(p) \
    ((uint32_t)(*((const uint8_t*)(p) + 3) << 24) | \
     (uint32_t)(*((const uint8_t*)(p) + 2) << 16) | \
     (uint32_t)(*((const uint8_t*)(p) + 1) <<  8) | \
     (uint32_t)(*((const uint8_t*)(p))))

#define LETOHLL_UNALIGNED(p) \
    (((uint64_t)(LETOHL_UNALIGNED(p + 4)) << 32) | ((uint64_t)(LETOHL_UNALIGNED(p))))

#define BETOHS_UNALIGNED(p) \
    ((uint16_t)(*((const uint8_t*)(p)) << 8) | \
     (uint16_t)(*((const uint8_t*)(p) + 1)))

#define BETOHL_UNALIGNED(p) \
    ((uint32_t)(*((const uint8_t*)(p)) << 24) | \
     (uint32_t)(*((const uint8_t*)(p) + 1) << 16) | \
     (uint32_t)(*((const uint8_t*)(p) + 2) <<  8) | \
     (uint32_t)(*((const uint8_t*)(p) + 3)))

#define BETOHLL_UNALIGNED(p) \
    (((uint64_t)(BETOHL_UNALIGNED(p)) << 32) | ((uint64_t)(BETOHL_UNALIGNED(p + 4))))

#endif

