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
// dt_option.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef DATA_DATA_TYPES_DT_OPTION_H
#define DATA_DATA_TYPES_DT_OPTION_H

#include <string>
#include <vector>
#include <iostream>

class Option
{
public:
    Option(std::string val, int depth);
    Option(const std::string& name, int val, int depth);
    Option(const std::string& name, bool val, int depth);
    Option(const std::string& name, std::string val, int depth);
    virtual ~Option() = default;

    inline const std::string& get_name()
    { return name; }

    inline const std::string& get_value()
    { return value; }

    void set_print_whitespace(bool w)
    { print_whitespace = w; }

    // overloading operators
    friend std::ostream& operator<<(std::ostream&, const Option&);
    friend bool operator!=(const Option& lhs, const Option& rhs);
    friend bool operator==(const Option& lhs, const Option& rhs);

private:
    enum class OptionType { STRING, VAR, BOOL, INT };

    std::string name;
    std::string value;
    int depth;
    bool print_whitespace = false;
    OptionType type;
};

#endif

