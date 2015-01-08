//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// codec.h author Josh Rosenbaum <jrosenba@cisco.com>

#include "framework/codec.h"

EncState::EncState(const ip::IpApi& api, EncodeFlags f, uint8_t pr,
        uint8_t t, uint16_t data_size) :
        ip_api(api),
        flags(f),
        dsize(data_size),
        next_ethertype(0),
        next_proto(pr),
        ttl(t)
{ }


uint8_t EncState::get_ttl(uint8_t lyr_ttl) const
{
    if (forward(flags))
    {
        if (flags & ENC_FLAG_TTL)
            return ttl;
        else
            return lyr_ttl;
    }
    else
    {
        uint8_t new_ttl;

        if (flags & ENC_FLAG_TTL)
            new_ttl = ttl;
        else
            new_ttl = MAX_TTL - lyr_ttl;

        if (new_ttl < MIN_TTL)
            new_ttl = MIN_TTL;

        return new_ttl;
    }
}



/* Logic behind 'buf + size + 1' -- we're encoding the
 * packet from the inside out.  So, whenever we add
 * data, 'allocating' N bytes means moving the pointer
 * N characters farther from the end. For this scheme
 * to work, an empty Buffer means the data pointer is
 * invalid and is actually one byte past the end of the
 * array
 */
Buffer::Buffer(uint8_t* buf, uint32_t size) :
    base(buf + size + 1),
    end(0),
    max_len(size),
    off(0)
{ }

