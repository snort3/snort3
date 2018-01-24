//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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
# define bswap_64(a) bswap64(a)
#endif

#ifdef __linux__
# include <byteswap.h>
#endif

#ifndef __APPLE__
# define htonll(a) ( 1 == htonl(1) ? (a) : bswap_64(a) )
# define ntohll(a) ( 1 == ntohl(1) ? (a) : bswap_64(a) )
#endif

#endif
