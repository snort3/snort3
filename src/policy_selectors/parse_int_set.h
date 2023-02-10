//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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
// parse_int_set.h author Ron Dempster <rdempste@cisco.com>

#ifndef PARSE_INT_SET_H
#define PARSE_INT_SET_H

// used to parse an int set

#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include "framework/value.h"

template<typename T>
static bool parse_int_set(const snort::Value& v, std::vector<T>& set)
{
    assert(v.get_type() == snort::Value::VT_STR);

    set.clear();

    std::string pl = v.get_string();

    std::stringstream ss(pl);
    ss >> std::setbase(0);

    int64_t n;

    while ( ss >> n )
    {
        if ( n > std::numeric_limits<T>::max() )
            return false;

        set.emplace_back(n);
    }
    if ( !ss.eof() )
        return false;

    return true;
}

#endif

