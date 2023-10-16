//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// range.h author Russ Combs <rucombs@cisco.com>

#ifndef FRAMEWORK_RANGE_H
#define FRAMEWORK_RANGE_H

// RangeCheck supports common IpsOption evaluation syntax and semantics.

#include "main/snort_types.h"

// unfortunately, <> was implemented inconsistently.  eg:
// dsize implements <> as ( a <= c && c <= b ) and
// icode implements <> as ( a < c && c < b )

// <> is implemented icode style but we add explicit options
// <=> for dsize style and >< for icode style so rule options
// can coerce <> if needed for backwards compatibility

namespace snort
{
class SO_PUBLIC RangeCheck
{
public:
    enum Op
    {
        // =  !  <   <=  >   >=  <>  <=>
        EQ, NOT, LT, LE, GT, GE, LG, LEG, MAX
    };

    Op op = MAX;
    int64_t min = 0;
    int64_t max = 0;

    bool operator==(const RangeCheck&) const;

    void init();
    bool is_set() const;
    // FIXIT-L add ttl style syntax
    bool parse(const char* s);
    bool eval(int64_t) const;
    bool validate(const char* s, const char* r);
    uint32_t hash() const;
};
}
#endif

