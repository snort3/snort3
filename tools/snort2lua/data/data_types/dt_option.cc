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
// dt_option.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "data/data_types/dt_option.h"

Option::Option(std::string val, int d)
{
    this->depth = d;

    if (val.front() == '$')
    {
        val.erase(val.begin());
        this->value = std::string(val);
        this->type = OptionType::VAR;
    }
    else
    {
        this->value = std::string(val);
        this->type = OptionType::STRING;
    }
}

Option::Option(const std::string& n, int val, int d)
{
    this->name = n;
    this->value = std::to_string(val);
    this->depth = d;
    this->type = OptionType::INT;
}

Option::Option(const std::string& n, bool v, int d)
{
    this->name = n;
    this->value = (v) ? "true" : "false";
    this->depth = d;
    this->type = OptionType::BOOL;
}

Option::Option(const std::string& opt_name, std::string val, int d)
{
    this->name = opt_name;
    this->depth = d;

    if (val.front() == '$')
    {
        val.erase(val.begin());
        this->value = std::string(val);
        this->type = OptionType::VAR;
    }
    else
    {
        this->value = std::string(val);
        this->type = OptionType::STRING;
    }
}

std::ostream& operator<<(std::ostream& out, const Option& o)
{
    std::string whitespace;

    for (int i = 0; i < o.depth; i++)
        whitespace += "    ";

    if ( o.print_whitespace )
        out << whitespace;

    if (!o.name.empty())
        out << o.name << " = ";

    switch (o.type)
    {
    case Option::OptionType::STRING:
        out << '\'' << o.value << '\'';
        break;

    case Option::OptionType::BOOL:
    case Option::OptionType::INT:
    case Option::OptionType::VAR:
        out << o.value;
        break;
    }
    return out;
}

bool operator==(const Option& lhs, const Option& rhs)
{
    return ((lhs.name == rhs.name) &&
           lhs.type == rhs.type &&
           (lhs.value == rhs.value));
}

bool operator!=(const Option& lhs, const Option& rhs)
{
    return !(lhs == rhs);
}

