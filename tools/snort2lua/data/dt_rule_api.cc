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
// dt_data.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <iostream>
#include <sstream>
#include <cstring>
#include "data/dt_rule_api.h"
#include "data/dt_data.h"

#include "utils/s2l_util.h"


RuleApi rule_api;

RuleApi::RuleApi()
    :   curr_rule(nullptr),
        curr_data_bad(false)
{
    bad_rules = new Comments(start_bad_rules, 0,
                    Comments::CommentType::MULTI_LINE);
}

RuleApi::~RuleApi()
{
    for (auto r : rules)
        delete r;

    delete bad_rules;
}

void RuleApi::reset_state()
{
    curr_rule = nullptr;
    curr_rule_opt = nullptr;
    curr_data_bad = false;
}


void RuleApi::begin_rule()
{
    if (curr_rule == nullptr)
    {
        curr_rule = new Rule();
        rules.push_back(curr_rule);
        curr_data_bad = false;
    }
}

void RuleApi::make_rule_a_comment()
{
    if (!curr_rule)
        begin_rule();

    curr_rule->make_comment();
}

void RuleApi::bad_rule(std::istringstream& stream, std::string bad_option)
{
    if (!curr_rule)
        begin_rule();

    // we only need to go through this once.
    if (!curr_data_bad)
    {
        bad_rules->add_text(std::string());
        bad_rules->add_text("Failed to convert rule: " + stream.str() + ")");
        curr_rule->bad_rule();
        curr_data_bad = true;
    }
    bad_rules->add_text("^^^^ unkown_option=" + bad_option);
}

bool RuleApi::add_hdr_data(std::string data)
{

    if (!curr_rule)
        begin_rule();

    return curr_rule->add_hdr_data(data);
}

void RuleApi::update_rule_type(std::string new_type)
{
    if (!curr_rule)
    {
        begin_rule();
        curr_rule->add_hdr_data(new_type);
    }
    else
    {
        curr_rule->update_rule_type(new_type);
    }
}


bool RuleApi::add_rule_option(std::string opt_name)
{
    if (!curr_rule)
        begin_rule();

    return curr_rule->add_option(opt_name);
}

bool RuleApi::add_rule_option(std::string opt_name, std::string val)
{
    if (!curr_rule)
        begin_rule();

    return curr_rule->add_option(opt_name, val);
}


bool RuleApi::add_rule_option_before_selected(std::string keyword,
                                            std::string val)
{

    if (!curr_rule_opt)
    {
        data_api.developer_error("Select an option before placing a "
                "new option before selected option");
        return false;
    }

    return curr_rule->add_option_before_selected(curr_rule_opt, keyword, val);
}

bool RuleApi::add_suboption(std::string keyword)
{
    if (curr_rule_opt)
        return curr_rule_opt->add_suboption(keyword);

    data_api.developer_error("Select an option before adding a suboption!!");
    return false;
}

bool RuleApi::add_suboption(std::string keyword,
                            std::string val)
{
    if (curr_rule_opt)
        return curr_rule_opt->add_suboption(keyword, val);

    data_api.developer_error("Select an option before adding a suboption!!");
    return false;
}

bool RuleApi::select_option(std::string opt_name)
{
    // using add_comment here so this error is right above the failed rule
    if (curr_rule)
    {
        curr_rule_opt = curr_rule->select_option(opt_name);
        if (curr_rule_opt != nullptr)
            return true;
        else
            data_api.developer_error("Option " + opt_name + "never created for following rule:");
    }
    else
    {
        data_api.developer_error("Must begin a rule before selecting an option!");
    }

    return false;
}

void RuleApi::unselect_option()
{
    curr_rule_opt = nullptr;
}

void RuleApi::add_comment_to_rule(std::string comment)
{
    if (!curr_rule)
        begin_rule();

    curr_rule->add_comment(comment);
}

std::ostream& operator<<( std::ostream &out, const RuleApi& data)
{
    if (data_api.is_default_mode())
    {
        if (!data.bad_rules->empty())
            out << (*data.bad_rules) << "\n";
    }


    out << "default_rules =\n[[\n";
    for (Rule* r : data.rules)
        out << (*r) << "\n\n";

    out << "]]\n\n\n";


    return out;
}

void RuleApi::print_rules(std::ostream& out, bool in_rule_file)
{
    if (!in_rule_file)
        out << "default_rules =\n[[\n";

    for (Rule* r : rules)
        out << (*r) << "\n";

    if (!in_rule_file)
        out << "]]\n\n";
}

void RuleApi::print_rejects(std::ostream& out)
{
    if (data_api.is_default_mode())
    {
        if (!bad_rules->empty())
            out << (*bad_rules) << "\n\n";
    }
}


void RuleApi::swap_rules(std::vector<Rule*>& new_rules)
{ rules.swap(new_rules); }
