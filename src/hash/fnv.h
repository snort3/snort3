//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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
// fnv.h author Brandon Stultz <brastult@cisco.com>
// based on https://datatracker.ietf.org/doc/html/draft-eastlake-fnv

#ifndef FNV_H
#define FNV_H

#define FNV_PRIME 0x00000100000001B3
#define FNV_BASIS 0xCBF29CE484222325

//--------------------------------------------------------------------------
// FNV-1a Hash
//--------------------------------------------------------------------------

inline uint64_t fnv1a(const char* buf, const size_t len)
{
    uint64_t result = FNV_BASIS;

    for (size_t i = 0; i < len; i++)
        result = (result ^ static_cast<uint8_t>(buf[i])) * FNV_PRIME;

    return result;
}

#endif
