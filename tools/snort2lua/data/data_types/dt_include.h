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
// dt_include.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef DATA_DATA_TYPES_DT_INCLUDE_H
#define DATA_DATA_TYPES_DT_INCLUDE_H

#include <string>
#include <iostream>

class Include
{
public:

    Include(const std::string& file_name);
    virtual ~Include() = default;

    // overloading operators
    friend std::ostream& operator<<(std::ostream&, const Include&);

    friend bool operator==(const Include& lhs, const Include& rhs);
    friend bool operator!=(const Include& lhs, const Include& rhs);

private:
    std::string file_name;
};

#endif

