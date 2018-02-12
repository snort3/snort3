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
// rd_option.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "data/data_types/dt_rule_option.h"
#include "data/data_types/dt_rule_suboption.h"

RuleOption::RuleOption(const std::string& n) :
    name(n),
    value(std::string())
{ }

RuleOption::RuleOption(const std::string& n, const std::string& v)
    :   name(n),
    value(v)
{ }

RuleOption::~RuleOption()
{
    for (auto rso : sub_options)
        delete rso;
}

bool RuleOption::add_suboption(const std::string& subopt_name)
{
    RuleSubOption* subopt = new RuleSubOption(subopt_name);
    sub_options.push_back(subopt);
    return true;
}

bool RuleOption::add_suboption(const std::string& subopt_name,
    const std::string& val)
{
    RuleSubOption* subopt = new RuleSubOption(subopt_name, val);
    sub_options.push_back(subopt);
    return true;
}

std::ostream& operator<<(std::ostream& out, const RuleOption& opt)
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

