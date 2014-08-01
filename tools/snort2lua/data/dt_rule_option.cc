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
// rd_option.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "data/dt_rule_option.h"



RuleOption::RuleOption(std::string name) :
        name(name),
        value(std::string())
{}

RuleOption::RuleOption(std::string name, std::string value)
    :   name(name),
        value(value)
{}

RuleOption::~RuleOption()
{
}

bool RuleOption::add_suboption(std::string name)
{
    RuleSubOption* subopt = new RuleSubOption(name);
    sub_options.push_back(subopt);
    return true;
}

bool RuleOption::add_suboption(std::string name,
                                std::string val)
{
    RuleSubOption* subopt = new RuleSubOption(name, val);
    sub_options.push_back(subopt);
    return true;
}


std::ostream &operator<<( std::ostream& out, const RuleOption &opt)
{
    bool first_print = true;

    out << opt.name;

    if (!opt.value.empty())
    {
        out << ':' << opt.value;
        first_print = false;
    }
    else if (!opt.sub_options.empty())
    {
        out << ':' << opt.value;
    }

    for (RuleSubOption* rso : opt.sub_options)
    {
        if (first_print)
            first_print = false;
        else
            out << ",";

        out << (*rso);
    }

    return out;
}
