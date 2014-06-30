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
// dt_data.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include "dt_data.h"
#include "util/util.h"
#include <iostream>
#include <sstream>


static const std::string start_comments =
    "COMMENTS:\n"
    "    these line were originally commented out or empty"
    "in the configuration file.";

static const std::string start_errors =
    "ERRORS:\n"
    "    all of these occured during the attempted conversion:\n\n";

static const std::string start_bad_rules =
    "FAILED RULES CONVERSIONS:\n"
    "    These rules has invalid rule options\n\n";

static inline Table* find_table(std::vector<Table*> vec, std::string name)
{
    if(name.empty())
        return nullptr;
    
    for( auto *t : vec)
        if(!name.compare(t->get_name()))
            return t;

    return nullptr;
}

LuaData::LuaData()
    :   curr_rule(nullptr),
        curr_rule_opt(nullptr),
        curr_rule_bad(false)
{
    comments = new Comments(start_comments, 0,
                    Comments::CommentType::MULTI_LINE);
    errors = new Comments(start_errors, 0,
                    Comments::CommentType::MULTI_LINE);
    bad_rules = new Comments(start_bad_rules, 0,
                    Comments::CommentType::MULTI_LINE);
}

LuaData::~LuaData()
{
    for (auto *v : vars)
        delete v;

    for (auto t : tables)
        delete t;

    for (auto r : rules)
        delete r;

    delete comments;
    delete errors;
    delete bad_rules;
}


void LuaData::add_reject_comment(std::string comment)
{
    comments->add_text(comment);
}


bool LuaData::add_variable(std::string name, std::string value)
{
    for (auto v : vars)
        if(v->get_name() == name)
            return v->add_value(value);

    Variable *var = new Variable(name);
    vars.push_back(var);
    return var->add_value(value);
}


void LuaData::reset_state()
{
    std::stack<Table*> empty;
    open_tables.swap(empty );
    curr_rule = nullptr;
    curr_rule_opt = nullptr;
}

void LuaData::open_top_level_table(std::string table_name)
{
    Table *t = find_table(tables, table_name);

    if (t == nullptr)
    {
        t = new Table(table_name, 0);
        tables.push_back(t);
    }

    open_tables.push(t);
}

void LuaData::open_table(std::string table_name)
{
    Table *t;

    // if no open tables, create a top-level table
    if (open_tables.size() > 0)
    {
        t = open_tables.top()->open_table(table_name);
    }
    else
    {
        t = find_table(tables, table_name);

        if (t == nullptr)
        {
            t = new Table(table_name, 0);
            tables.push_back(t);
        }
    }

    open_tables.push(t);
}

void LuaData::open_table()
{
    // if no open tables, create a top-level table
    if (open_tables.size() == 0)
    {
        add_error_comment("A nameless table must be nested inside a table!!");
    }
    else
    {
        Table *t = open_tables.top()->open_table();
        open_tables.push(t);
    }
}

void LuaData::close_table()
{
    if (open_tables.size() == 0)
        add_error_comment("No open tables to close!!");
    else
        open_tables.pop();
}



void LuaData::add_error_comment(std::string error_string)
{
    errors->add_text(error_string + "\n");
}


bool LuaData::add_option_to_table(const std::string option_name, const std::string val)
{
    if(open_tables.size() == 0)
    {
        add_error_comment("Must open table before adding an option!!: " +
            option_name + " = " + val);
        return false;
    }

    Table *t = open_tables.top();
    t->add_option(option_name, val);
    return true;
}

bool LuaData::add_option_to_table(const std::string option_name, const int val)
{
    if(open_tables.size() == 0)
    {
        add_error_comment("Must open table before adding an option!!: " +
            option_name + " = " + std::to_string(val));
        return false;
    }

    Table *t = open_tables.top();
    t->add_option(option_name, val);
    return true;
}

bool LuaData::add_option_to_table(const std::string option_name, const bool val)
{
    if(open_tables.size() == 0)
    {
        add_error_comment("Must open table before adding an option!!: " +
            option_name + " = " + std::to_string(val));
        return false;
    }

    Table *t = open_tables.top();
    t->add_option(option_name, val);
    return true;
}

// compilers are fickle and dangerous creatures.  Ensure a literal gets
// sent here rather to become a bool
bool LuaData::add_option_to_table(const std::string name, const char* v)
{
    return add_option_to_table(name, std::string(v));
}

bool LuaData::add_list_to_table(std::string list_name, std::string next_elem)
{
    if(open_tables.size() == 0)
    {
        add_error_comment("Must open table before adding an option!!: " +
            list_name + " = " + next_elem);
        return false;
    }

    Table *t = open_tables.top();

    if(t)
    {
        t->add_list(list_name, next_elem);
        return true;
    }
    else
    {
        add_error_comment("Must open table before adding an list!!: " +
            list_name + " += " + next_elem);
        return false;
    }
}

bool LuaData::add_comment_to_table(std::string comment)
{
    if (open_tables.size() == 0)
    {
        add_error_comment("Must open table before adding an option!!: '" +
            comment + "'");
        return false;
    }

    open_tables.top()->add_comment(comment);
    return true;
}

bool LuaData::add_diff_option_comment(std::string orig_var, std::string new_var)
{
    std::string error_string = "option change: '" + orig_var + "' --> '"
            + new_var + "'";

    if (open_tables.size() == 0)
    {
        add_error_comment("Must open table before adding an option!!: " +
            orig_var + " = " + new_var);
        return false;
    }

    open_tables.top()->add_comment(error_string);
    return true;
}


bool LuaData::add_deprecated_comment(std::string dep_var)
{
    std::string error_string = "option deprecated: '" + dep_var + "'";

    if (open_tables.size() == 0)
    {
        add_error_comment("Must open table before adding deprecated comment!!: " +
            dep_var);
        return false;
    }

    open_tables.top()->add_comment(error_string);
    return true;
}

// RULE PARSING

void LuaData::begin_rule()
{
    if (curr_rule != nullptr)
    {
        add_error_comment("Attempted to add a nested rules!!");
    }
    else
    {
        curr_rule = new Rule();
        rules.push_back(curr_rule);
        curr_rule_bad = false;
    }
}

void LuaData::make_rule_a_comment()
{
    curr_rule->make_comment();
}

void LuaData::bad_rule(std::string bad_option, std::istringstream& stream)
{
    // we only need to go through this once.
    if (!curr_rule_bad)
    {
        bad_rules->add_text("Failed to convert rule: first_unkown_option=" + bad_option +
                "\n        bad_rule: " + stream.str());
        curr_rule->bad_rule();
        curr_rule_bad = true;
    }
}

bool LuaData::add_hdr_data(std::string data)
{
    if (curr_rule)
        return curr_rule->add_hdr_data(data);

    add_error_comment("Must begin a rule before adding a header!");
    return false;
}

bool LuaData::add_rule_option(std::string opt_name)
{
    if (curr_rule)
        return curr_rule->add_option(opt_name);

    add_error_comment("Must begin a rule before adding an option!");
    return false;
}

bool LuaData::add_rule_option(std::string opt_name, std::string val)
{
    if (curr_rule)
        return curr_rule->add_option(opt_name, val);

    add_error_comment("Must begin a rule before adding an option!");
    return false;
}


bool LuaData::add_rule_option_before_selected(std::string keyword,
                                            std::string val)
{
    if (!curr_rule_opt)
    {
        comments->add_text("Select an option before placing a "
                "new option before selected option");
        return false;
    }

    return curr_rule->add_option_before_selected(curr_rule_opt, keyword, val);
}

bool LuaData::add_suboption(std::string keyword)
{
    if (curr_rule_opt)
        return curr_rule_opt->add_suboption(keyword);

    add_error_comment("Select an option before adding a suboption!!");
    return false;
}

bool LuaData::add_suboption(std::string keyword,
                            std::string val,
                            char delimeter)
{
    if (curr_rule_opt)
        return curr_rule_opt->add_suboption(keyword, val, delimeter);

    add_error_comment("Select an option before adding a suboption!!");
    return false;
}

bool LuaData::select_option(std::string opt_name)
{
    // using add_comment here so this error is right above the failed rule

    if (curr_rule)
    {
        curr_rule_opt = curr_rule->select_option(opt_name);
        if (curr_rule_opt != nullptr)
            return true;
        else
            comments->add_text("Option " + opt_name + "never created for following rule:");
    }
    else
    {
        comments->add_text("Must begin a rule before selecting an option!");
    }

    return false;
}

void LuaData::unselect_option()
{
    curr_rule_opt = nullptr;
}

void LuaData::add_comment_to_rule(std::string comment)
{
    curr_rule->add_comment(comment);
}

std::ostream& operator<<( std::ostream &out, const LuaData &data)
{
    out << (*data.errors) << std::endl << std::endl;

    for (Variable* v : data.vars)
        out << (*v) << "\n\n";


    out << (*data.bad_rules) << "\n\n";

    out << "default_rules =\n[[\n";
    for (Rule* r : data.rules)
        out << (*r) << "\n\n";

    out << "]]\n";

    for (Table* t : data.tables)
        out << (*t) << "\n\n";

    out << (*data.comments) << std::endl;


    return out;
}
