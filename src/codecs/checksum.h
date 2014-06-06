/*
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
// checksum.h author Josh Rosenbaum <jorosenba@cisco.com>

#ifndef CHECKSUM_H
#define CHECKSUM_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <stdlib.h>


namespace checksum
{

struct Pseudoheader6
{
    uint32_t sip[4], dip[4];
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t len;
};


struct Pseudoheader
{
    uint32_t sip, dip;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t len;
};


uint16_t cksum_add(const uint16_t *buf, size_t len);
uint16_t tcp_cksum(const uint16_t *buf, size_t len, Pseudoheader*);
uint16_t tcp_cksum(const uint16_t *buf, size_t len, Pseudoheader6 *ph );
uint16_t udp_cksum(const uint16_t *buf, size_t len, Pseudoheader*);
uint16_t udp_cksum(const uint16_t *buf, size_t len, Pseudoheader6*);
uint16_t icmp_cksum(const uint16_t *buf, size_t len, Pseudoheader6*);
uint16_t icmp_cksum(const uint16_t *buf, size_t len);
uint16_t ip_cksum(const uint16_t *buf, size_t len);

} // namespace checksum

#endif