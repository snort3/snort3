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
// ipv6_util.h author Josh Rosenbaum <jorosenba@cisco.com>


#include "protocols/ipv6.h"
#include "protocols/protocol_ids.h"
#include "protocols/packet.h"

namespace ipv6_util
{

bool CheckIPV6HopOptions(const uint8_t *pkt, uint32_t len, Packet *p);
void CheckIPv6ExtensionOrder(Packet *p);

static inline int IPV6ExtensionOrder(uint8_t type)
{
    switch (type)
    {
        case IPPROTO_ID_HOPOPTS:   return 1;
        case IPPROTO_ID_DSTOPTS:   return 2;
        case IPPROTO_ID_ROUTING:   return 3;
        case IPPROTO_ID_FRAGMENT:  return 4;
        case IPPROTO_ID_AH:        return 5;
        case IPPROTO_ID_ESP:       return 6;
        default:                   return 7;
    }
}

} // namespace ipv6_util
