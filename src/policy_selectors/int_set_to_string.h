//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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
// int_set_to_string.h author Ron Dempster <rdempste@cisco.com>

#ifndef INT_SET_TO_STRING_H
#define INT_SET_TO_STRING_H

// used to format configuration for output in show methods

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

template <typename T>
static std::string int_set_to_string(const std::vector<T>& v)
{
    if (v.empty())
        return "";

    std::stringstream ss;
    for (auto e : v)
        ss << e << " ";

    auto str = ss.str();
    if (!str.empty())
        str.pop_back();

    return str;
}

#endif

