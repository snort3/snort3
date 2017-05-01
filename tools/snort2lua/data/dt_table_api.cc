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
// dt_table_api.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <iostream>
#include <sstream>
#include <cstring>

#include "data/dt_table_api.h"
#include "data/dt_data.h"
#include "helpers/s2l_util.h"
#include "data/data_types/dt_table.h"
#include "data/data_types/dt_var.h"
#include "data/data_types/dt_comment.h"
#include "data/data_types/dt_rule.h"
#include "data/data_types/dt_include.h"

TableApi::TableApi() :  curr_data_bad(false) { }

TableApi::~TableApi()
{
    for (auto t : tables)
        delete t;
}

void TableApi::reset_state()
{
    std::stack<Table*> empty;
    open_tables.swap(empty);
    std::stack<unsigned> empty_two;
    top_level_tables.swap(empty_two);
    curr_data_bad = false;
}

void TableApi::open_top_level_table(std::string table_name)
{
    Table* t = util::find_table(tables, table_name);

    if (t == nullptr)
    {
        t = new Table(table_name, 0);
        tables.push_back(t);
    }

    open_tables.push(t);

    // ignore the initial table
    if (open_tables.size() > 1)
        top_level_tables.push(open_tables.size());
}

void TableApi::open_table(std::string table_name)
{
    Table* t;

    // if no open tables, create a top-level table
    if (open_tables.size() > 0)
    {
        t = open_tables.top()->open_table(table_name);
    }
    else
    {
        t = util::find_table(tables, table_name);

        if (t == nullptr)
        {
            t = new Table(table_name, 0);
            tables.push_back(t);
        }
    }

    open_tables.push(t);
}

void TableApi::open_table()
{
    // if no open tables, create a top-level table
    if (open_tables.size() == 0)
    {
        DataApi::developer_error("A nameless table must be nested inside a table!!");
    }
    else
    {
        Table* t = open_tables.top()->open_table();
        open_tables.push(t);
    }
}

void TableApi::close_table()
{
    if (open_tables.size() == 0)
        DataApi::developer_error("No open tables to close!!");
    else
    {
        if ( !top_level_tables.empty() )
            if ( open_tables.size() == top_level_tables.top() )
                top_level_tables.pop();

        open_tables.pop();
    }
}

bool TableApi::add_option(const std::string val)
{
    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open table before adding an option!!: "
            "<anonymous> = " + val);
        return false;
    }

    Table* t = open_tables.top();
    t->add_option(val);
    return true;
}

bool TableApi::add_option(const std::string option_name, const std::string val)
{
    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open table before adding an option!!: " +
            option_name + " = " + val);
        return false;
    }

    Table* t = open_tables.top();
    t->add_option(option_name, val);
    return true;
}

bool TableApi::add_option(const std::string option_name, const int val)
{
    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open table before adding an option!!: " +
            option_name + " = " + std::to_string(val));
        return false;
    }

    Table* t = open_tables.top();
    t->add_option(option_name, val);
    return true;
}

bool TableApi::add_option(const std::string option_name, const bool val)
{
    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open table before adding an option!!: " +
            option_name + " = " + std::to_string(val));
        return false;
    }

    Table* t = open_tables.top();
    t->add_option(option_name, val);
    return true;
}

// compilers are fickle and dangerous creatures.  Ensure a literal gets
// sent here rather to become a bool
bool TableApi::add_option(const char* const v)
{ return add_option(std::string(v)); }

bool TableApi::add_option(const std::string name, const char* const v)
{ return add_option(name, std::string(v)); }

void TableApi::create_append_data(std::string& fqn, Table*& t)
{
    unsigned start = 0;

    if (!top_level_tables.empty())
        start = top_level_tables.top();

    // I need to iterate over the stack of open tables.  However,
    // stack's don't allow iteration without popping.  So, rather
    // than change the underlying stack data structure, I am going
    // to just copy the entire data structure.  Inefficient, but
    // not pressed for speed here.
    std::stack<Table*> copy(open_tables);

    while (!copy.empty() && copy.size() >= start)
    {
        fqn = copy.top()->get_name() + "." + fqn;
        t = copy.top();
        copy.pop();
    }
}

void TableApi::append_option(const std::string option_name, const std::string val)
{
    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open table before adding an option!!: " +
            option_name + " = " + val);
        return;
    }

    Table* t = nullptr;
    std::string opt_name = option_name;
    create_append_data(opt_name, t);

    if ( t != nullptr)
        t->append_option(opt_name, val);
    else
        DataApi::developer_error("Snort2lua cannot find a Table to append the option: "
            + option_name + " = " + val);
}

void TableApi::append_option(const std::string option_name, const int val)
{
    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open table before adding an option!!: " +
            option_name + " = " + std::to_string(val));
        return;
    }

    Table* t = nullptr;
    std::string opt_name = option_name;
    create_append_data(opt_name, t);

    if ( t != nullptr)
        t->append_option(opt_name, val);
    else
        DataApi::developer_error("Snort2lua cannot find a Table to append the option: "
            + opt_name + " = " + std::to_string(val));
}

void TableApi::append_option(const std::string option_name, const bool val)
{
    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open table before adding an option!!: " +
            option_name + " = " + std::to_string(val));
        return;
    }

    Table* t = nullptr;
    std::string opt_name = option_name;
    create_append_data(opt_name, t);

    if ( t != nullptr)
        t->append_option(opt_name, val);
    else
        DataApi::developer_error("Snort2lua cannot find a Table to append the option: "
            + opt_name + " = " + std::to_string(val));
}

void TableApi::append_option(const std::string name, const char* const v)
{ append_option(name, std::string(v)); }

bool TableApi::add_list(std::string list_name, std::string next_elem)
{
    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open table before adding an option!!: " +
            list_name + " = " + next_elem);
        return false;
    }

    Table* t = open_tables.top();

    if (t)
    {
        t->add_list(list_name, next_elem);
        return true;
    }
    else
    {
        DataApi::developer_error("Must open table before adding an list!!: " +
            list_name + " += " + next_elem);
        return false;
    }
}

bool TableApi::add_comment(std::string comment)
{
    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open table before adding comment !!: '" +
            comment + "'");
        DataApi::developer_error("comment added to as a general lua comment");
//        data_api.add_comment(comment);
        return false;
    }

    open_tables.top()->add_comment(comment);
    return true;
}

bool TableApi::option_exists(const std::string name)
{
    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open table before calling option_exists() !!");
        return false;
    }

    return open_tables.top()->has_option(name);
}

bool TableApi::add_diff_option_comment(std::string orig_var, std::string new_var)
{
    std::string error_string = "option change: '" + orig_var + "' --> '"
        + new_var + "'";

    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open table before adding an option!!: " +
            orig_var + " = " + new_var);
        return false;
    }

    open_tables.top()->add_comment(error_string);
    return true;
}

bool TableApi::add_deleted_comment(std::string dep_var)
{
    std::string error_string = "option deleted: '" + dep_var + "'";

    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open a table before adding "
            "deprecated comment!!: " + dep_var);
        return false;
    }

    open_tables.top()->add_comment(error_string);
    return true;
}

bool TableApi::add_unsupported_comment(std::string unsupported_var)
{
    std::string unsupported_str = "option '" + unsupported_var +
        "' is currently unsupported";

    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open a table before adding an "
            "'unsupported' comment");
        return false;
    }

    open_tables.top()->add_comment(unsupported_str);
    return true;
}

std::ostream& operator<<(std::ostream& out, const TableApi& table)
{
    for (Table* t : table.tables)
        out << (*t) << "\n\n";
    out << "\n\n";

    return out;
}

void TableApi::print_tables(std::ostream& out)
{
    for (Table* t : tables)
        out << (*t) << "\n\n";
    out << "\n\n";
}

void TableApi::swap_tables(std::vector<Table*>& new_tables)
{
    tables.swap(new_tables);
}

bool TableApi::get_option_value(const std::string name, std::string& value)
{
    if (open_tables.size() == 0)
    {
        DataApi::developer_error("Must open table before calling option_exists() !!");
        return false;
    }

    return open_tables.top()->get_option(name, value);
}

