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
// nhttp_infractions.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_INFRACTIONS_H
#define NHTTP_INFRACTIONS_H

#include <assert.h>

//-------------------------------------------------------------------------
// Infractions class
//-------------------------------------------------------------------------

class NHttpInfractions
{
public:
    NHttpInfractions() { }
    NHttpInfractions(int inf) : infractions(1 << inf) { assert((inf >= 0) && (inf < 64)); }
    bool found_new(int inf)
    {
        assert((inf >= 0) && (inf < 64));
        const bool ret_val = ((1 << inf) & infractions & ~previous_infractions) != 0;
        previous_infractions |= (1 << inf) & infractions;
        return ret_val;
    }

    bool none_found() const { return infractions == 0; }
    NHttpInfractions& operator+=(const NHttpInfractions& rhs)
    {
        infractions |= rhs.infractions;
        previous_infractions |= rhs.previous_infractions; return *this;
    }

    friend NHttpInfractions operator+(NHttpInfractions lhs, const NHttpInfractions& rhs)
    {
        lhs +=
            rhs; return lhs;
    }
    friend bool operator&&(const NHttpInfractions& lhs, const NHttpInfractions& rhs)
    {
        return (lhs.infractions & rhs.infractions) != 0;
    }

    // The following two methods are for convenience of debug and test output only!
    // The 64-bit implementation will not be big enough forever and this interface cannot be all
    // over the code.
    uint64_t get_raw() const { return infractions; }
    uint64_t get_raw_prev() const { return previous_infractions; }

private:
    NHttpInfractions(uint64_t infractions_, uint64_t previous_infractions_) : infractions(
        infractions_),
        previous_infractions(previous_infractions_) { }

    uint64_t infractions = 0;
    uint64_t previous_infractions = 0;
};

#endif

