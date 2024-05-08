//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
// infractions.h author Tom Peters <thopeter@cisco.com>

#ifndef INFRACTIONS_H
#define INFRACTIONS_H

#include <bitset>
#include <cassert>

//-------------------------------------------------------------------------
// Infractions class
//-------------------------------------------------------------------------

template <int MAX, int NONE>
class Infractions
{
public:
    Infractions() = default;
    Infractions(int inf)
    {
        if (inf == NONE)
            return;
        assert((inf >= 0) && (inf < MAX));
        infractions[inf] = true;
    }
    Infractions& operator+=(const Infractions& rhs)
        { infractions |= rhs.infractions; return *this; }
    friend Infractions operator+(Infractions lhs, const Infractions& rhs)
        { lhs += rhs; return lhs; }
    friend bool operator&(const Infractions& lhs, const Infractions& rhs)
        { return (lhs.infractions & rhs.infractions) != 0; }

    bool none_found() const { return infractions == 0; }

    uint64_t get_raw(unsigned base) const { return
        ((infractions >> base) & std::bitset<MAX>(0xFFFFFFFFFFFFFFFF)).to_ulong(); }

private:
    std::bitset<MAX> infractions = 0;
};

#endif
