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


static const std::string start_comments =
    "COMMENTS:\n"
    "    these line were originally commented out or empty"
    "in the configuration file.";

static const std::string start_errors =
    "ERRORS:\n"
    "    all of these occured during the attempted conversion:\n\n";

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
{
    comments = new Comments(start_comments, 0,
                    Comments::CommentType::MULTI_LINE);
    errors = new Comments(start_errors, 0,
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
        add_error_comment("Must open table before adding an option!!: " +
            dep_var);
        return false;
    }

    open_tables.top()->add_comment(error_string);
    return true;
}

// RULE PARSING

void LuaData::begin_rule()
{
    curr_rule = new Rule();
    rules.push_back(curr_rule);
}

bool LuaData::add_hdr_data(std::string data)
{
    return curr_rule->add_hdr_data(data);
}


std::ostream& operator<<( std::ostream &out, const LuaData &data)
{
    out << (*data.errors) << std::endl << std::endl;

    for (Variable *v : data.vars)
        out << (*v) << std::endl << std::endl;

    for (Table *t : data.tables)
        out << (*t) << std::endl << std::endl;

    out << (*data.comments) << std::endl;


    return out;
}
