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
// gre.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_GRE_H
#define PROTOCOLS_GRE_H

#include <arpa/inet.h>

namespace snort
{
namespace gre
{
/* GRE related stuff */
struct GREHdr
{
    uint8_t flags;
    uint8_t version;
    uint16_t ether_type;

    inline uint8_t get_version() const
    { return version & 0x07; }

    inline ProtocolId proto() const
    { return (ProtocolId)ntohs(ether_type); }

    inline uint16_t raw_proto() const
    { return ether_type; }
};
} // namespace gre
} // namespace snort

#endif

