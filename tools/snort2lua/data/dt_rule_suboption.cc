/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// dt_rule_suboptions.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <string>
#include "data/dt_rule_suboption.h"


RuleSubOption::RuleSubOption(std::string name)
    :   name(name),
        value(std::string()),
        delimeter(':')
{
}

RuleSubOption::RuleSubOption(std::string name, std::string value, char delimeter)
    :   name(name),
        value(value),
        delimeter(delimeter)
{
}


RuleSubOption::~RuleSubOption()
{
}

// overloading operators
std::ostream &operator<<( std::ostream& out, const RuleSubOption& subopt)
{
    out << subopt.name;

    if (!subopt.value.empty())
        out << subopt.delimeter << subopt.value;

    return out;
}
