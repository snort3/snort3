//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// dt_rule.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "data/data_types/dt_rule.h"
#include "data/dt_data.h"  // included for print mode
#include "helpers/s2l_util.h"
#include "data/data_types/dt_rule_option.h"

Rule::Rule() :  num_hdr_data(0),
    is_bad_rule(false),
    is_comment(false)
{
}

Rule::~Rule()
{
    for (RuleOption* ro : options)
        delete ro;
}

bool Rule::add_hdr_data(std::string data)
{
    if (num_hdr_data < hdr_data.size())
    {
        hdr_data[num_hdr_data] = data;
        num_hdr_data++;
        return true;
    }
    else
    {
        is_bad_rule = true;
        return false;
    }
}

void Rule::update_rule_action(std::string new_type)
{ hdr_data[0] = new_type; }

void Rule::bad_rule()
{ is_bad_rule = true; }

void Rule::add_comment(std::string new_comment)
{ comments.push_back("# " + new_comment); }

void Rule::make_comment()
{ is_comment = true; }

void Rule::add_option(std::string keyword)
{
    RuleOption* r = new RuleOption(keyword);
    options.push_back(r);
}

void Rule::add_option(std::string keyword, std::string data)
{
    RuleOption* r = new RuleOption(keyword, data);
    options.push_back(r);
}

void Rule::add_suboption(std::string keyword)
{ options.back()->add_suboption(keyword); }

void Rule::add_suboption(std::string keyword, std::string val)
{ options.back()->add_suboption(keyword, val); }

void Rule::set_curr_options_buffer(std::string new_buffer, bool add_option)
{
    /* set the buffer if
     * 1) No buffer has been set and this is not the default "pkt_data" buffer
     * 2) The sticky buffer is set and is not equal to the new buffer
     */
    if ( (sticky_buffer.empty() && new_buffer.compare("pkt_data")) ||
        (!sticky_buffer.empty() && sticky_buffer.compare(new_buffer)) )
    {
        RuleOption* new_opt = new RuleOption(new_buffer);
        if ( add_option )
            options.push_back(new_opt);
        else
            options.insert(options.end() - 1, new_opt);
        sticky_buffer = new_buffer;
    }
}

std::ostream& operator<<(std::ostream& out, const Rule& rule)
{
    bool first_line = true;

    // don't print comment and tag in quiet mode
    if (!DataApi::is_quiet_mode())
    {
        for (std::string s : rule.comments)
            out << s << "\n";
    }

    if (rule.is_bad_rule || rule.is_comment)
        out << "#";

    for (std::size_t i = 0; i < rule.num_hdr_data; i++)
    {
        if (first_line)
            first_line = false;
        else
            out << " ";

        std::string tmp = rule.hdr_data[i];
        out << util::sanitize_lua_string(tmp);
    }

    if (!rule.options.empty())
    {
        out << " (";
        first_line = true;

        for (auto* r : rule.options)
        {
            if (first_line)
                first_line = false;
            else
                out << ";";
            out << " " << (*r);
        }

        out << "; )";
    }

    return out;
}

