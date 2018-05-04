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
// dt_data.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <iostream>
#include <sstream>
#include <cstring>

#include "helpers/s2l_util.h"
#include "data/dt_rule_api.h"
#include "data/dt_data.h"
#include "data/data_types/dt_comment.h"
#include "data/data_types/dt_rule.h"
#include "data/data_types/dt_rule_option.h"
#include "data/data_types/dt_rule_suboption.h"

std::size_t RuleApi::error_count = 0;
std::string RuleApi::remark;

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
    if (curr_rule && !remark.empty())
        curr_rule->add_option("rem", remark);

    curr_rule = nullptr;
    curr_data_bad = false;
}

bool RuleApi::failed_conversions() const
{ return error_count > 0; }

std::size_t RuleApi::num_errors() const
{ return error_count; }

bool RuleApi::empty() const
{ return rules.empty(); }

void RuleApi::clear()
{
    for (auto r : rules)
        delete r;

    rules.clear();
}

void RuleApi::set_remark(const char* s)
{ remark = s; }

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

void RuleApi::bad_rule(std::istringstream& stream, const std::string& bad_option)
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
        error_count++;
    }
    bad_rules->add_text("^^^^ unknown_option=" + bad_option);
}

void RuleApi::include_rule_file(const std::string& file_name)
{
    if (curr_rule)
    {
        DataApi::developer_error("Attempting to include a file while building a rule!");
    }
    else
    {
        begin_rule();
        curr_rule->add_hdr_data("include " + file_name);
        curr_rule = nullptr; //  ensure nothing else gets added to this rule,
                             //  especially remarks
    }
}

void RuleApi::add_hdr_data(const std::string& data)
{
    if (!curr_rule)
        begin_rule();

    curr_rule->add_hdr_data(data);
}

void RuleApi::update_rule_action(const std::string& new_type)
{
    if (!curr_rule)
    {
        begin_rule();
        curr_rule->add_hdr_data(new_type);
    }
    else
    {
        curr_rule->update_rule_action(new_type);
    }
}

void RuleApi::add_option(const std::string& opt_name)
{
    if (!curr_rule)
        begin_rule();

    curr_rule->add_option(opt_name);
}

void RuleApi::add_option(const std::string& opt_name, const std::string& val)
{
    if (!curr_rule)
        begin_rule();

    curr_rule->add_option(opt_name, val);
}

std::string RuleApi::get_option(const std::string& keyword)
{
    if (!curr_rule)
        return std::string();

    return curr_rule->get_option(keyword);
}

void RuleApi::update_option(const std::string& keyword, std::string& val)
{
    if (!curr_rule)
        return;

    curr_rule->update_option(keyword, val);
}

void RuleApi::add_suboption(const std::string& keyword)
{
    if (curr_rule)
        curr_rule->add_suboption(keyword);
    else
        DataApi::developer_error("Add some header data before adding content!!");
}

void RuleApi::add_suboption(const std::string& keyword,
    const std::string& val)
{
    if (curr_rule)
        curr_rule->add_suboption(keyword, val);
    else
        DataApi::developer_error("Add some header data before adding content!!");
}

void RuleApi::set_curr_options_buffer(const std::string& buffer, bool add_option)
{
    if (curr_rule)
        curr_rule->set_curr_options_buffer(buffer, add_option);
    else
        DataApi::developer_error("Add some header data before adding content!!");
}

void RuleApi::add_comment(const std::string& comment)
{
    if (!curr_rule)
        begin_rule();

    curr_rule->add_comment(comment);
}

void RuleApi::old_http_rule()
{
    if (!curr_rule)
        begin_rule();

    curr_rule->set_old_http_rule();
}

bool RuleApi::is_old_http_rule()
{
    if (!curr_rule)
        return false;

    return curr_rule->is_old_http_rule();
}

std::ostream& operator<<(std::ostream& out, const RuleApi& data)
{
    if (DataApi::is_default_mode())
    {
        if (!data.bad_rules->empty())
            out << (*data.bad_rules) << "\n";
    }

    out << "local_rules =\n[[\n";
    for (Rule* r : data.rules)
        out << (*r) << "\n\n";

    out << "]]\n\n\n";

    return out;
}

void RuleApi::print_rules(std::ostream& out, bool in_rule_file)
{
    if ( empty() )
        return;

    if (!in_rule_file)
        out << "local_rules =\n[[\n";

    for (Rule* r : rules)
        out << (*r) << "\n";

    if (!in_rule_file)
        out << "]]\n\n";
}

void RuleApi::print_rejects(std::ostream& out)
{
    if (DataApi::is_default_mode())
    {
        if (!bad_rules->empty())
            out << (*bad_rules) << "\n\n";
    }
}

void RuleApi::swap_rules(std::vector<Rule*>& new_rules)
{ rules.swap(new_rules); }

