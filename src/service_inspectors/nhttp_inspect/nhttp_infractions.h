//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_infractions.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_INFRACTIONS_H
#define NHTTP_INFRACTIONS_H

#include <assert.h>
#include <bitset>

#include "nhttp_enum.h"

//-------------------------------------------------------------------------
// Infractions class
//-------------------------------------------------------------------------

class NHttpInfractions
{
public:
    NHttpInfractions() { }
    NHttpInfractions(int inf) { assert((inf >= 0) && (inf < MAX)); infractions[inf] = true; }
    void reset() { infractions = 0; }
    bool none_found() const { return infractions == 0; }
    NHttpInfractions& operator+=(const NHttpInfractions& rhs)
        { infractions |= rhs.infractions; return *this; }
    friend NHttpInfractions operator+(NHttpInfractions lhs, const NHttpInfractions& rhs)
        { lhs += rhs; return lhs; }
    friend bool operator&(const NHttpInfractions& lhs, const NHttpInfractions& rhs)
        { return (lhs.infractions & rhs.infractions) != 0; }

    // The following methods are for convenience of debug and test output only!
    uint64_t get_raw() const { return
        (infractions & std::bitset<MAX>(0xFFFFFFFFFFFFFFFF)).to_ulong(); }
    uint64_t get_raw2() const { return
        ((infractions >> 64) & std::bitset<MAX>(0xFFFFFFFFFFFFFFFF)).to_ulong(); }

private:
    static const int MAX = NHttpEnums::INF__MAX_VALUE;
    std::bitset<MAX> infractions = 0;
};

#endif

