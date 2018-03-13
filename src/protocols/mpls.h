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
// mpls.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_MPLS_H
#define PROTOCOLS_MPLS_H

#include <cstdint>

namespace snort
{
namespace mpls
{
struct MplsHdr
{
    uint32_t label;
    uint8_t exp;
    uint8_t bos;
    uint8_t ttl;
};
} // namespace mpls

// FIXIT-L constexpr != const, they are orthogonal keywords
constexpr int MPLS_PAYLOADTYPE_ETHERNET = 1;
constexpr int MPLS_PAYLOADTYPE_IPV4 = 2;
constexpr int MPLS_PAYLOADTYPE_IPV6 = 3;
}
#endif

