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

TableApi::~TableApi()
{
    for (auto t : tables)
        delete t;
}

bool TableApi::should_delegate() const
{ return delegating; }

bool TableApi::should_delegate(const std::string& table_name) const
{
    if ( delegating )
        return true;

    if ( delegate == this )
        return false;

    auto d = delegations.find(table_name);
    if ( d != delegations.end() )
        return d->second;

    return false;
}

void TableApi::reset_state()
{
    // DO NOT RESET DELEGATE STATE. IT HAS ITS OWN LIFECYCLE.
    std::stack<Table*> empty;
    open_tables.swap(empty);
    std::stack<unsigned> empty_two;
    top_level_tables.swap(empty_two);
    curr_data_bad = false;
}

void TableApi::open_top_level_table(const std::string& table_name, bool one_line)
{
    if ( should_delegate(table_name) )
    {
        delegate->open_top_level_table(table_name, one_line);
        delegating++;
        return;
    }

    Table* t = util::find_table(tables, table_name);
    bool existed = (t != nullptr);

    if ( !existed )
    {
        t = new Table(table_name, 0);
        tables.push_back(t);
    }

    t->set_one_line(one_line);
    open_tables.push(t);

    // ignore the initial table
    if ( open_tables.size() > 1 )
        top_level_tables.push(open_tables.size());

    if ( !existed )
    {
        auto p = pending.find(table_name);
        if ( p != pending.end() )
        {
            auto& q = p->second;
            while ( q.size() )
            {
                q.front()(*this);
                q.pop();
            }

            pending.erase(p);
        }
    }
}

void TableApi::open_table(const std::string& table_name, bool one_line)
{
    if ( should_delegate(table_name) )
    {
        delegate->open_table(table_name, one_line);
        delegating++;
        return;
    }

    // if no open tables, create a top-level table
    if (!open_tables.empty())
    {
        Table* t = open_tables.top()->open_table(table_name);
        t->set_one_line(one_line);
        open_tables.push(t);
    }
    else
        open_top_level_table(table_name, one_line);
}

void TableApi::open_table(bool one_line)
{
    if ( should_delegate() )
    {
        delegate->open_table(one_line);
        delegating++;
        return;
    }

    // if no open tables, create a top-level table
    if (open_tables.empty())
    {
        DataApi::developer_error("A nameless table must be nested inside a table!!");
    }
    else
    {
        Table* t = open_tables.top()->open_table();
        t->set_one_line(one_line);
        open_tables.push(t);
    }
}

void TableApi::close_table()
{
    if ( should_delegate() )
    {
        delegate->close_table();
        delegating--;
        return;
    }

    if (open_tables.empty())
        DataApi::developer_error("No open tables to close!!");
    else
    {
        if ( !top_level_tables.empty() )
            if ( open_tables.size() == top_level_tables.top() )
                top_level_tables.pop();

        open_tables.pop();
    }
}

template<typename T>
bool TableApi::do_add_option(const std::string& opt_name, T val, const std::string& s_val)
{
    if ( should_delegate() )
        return delegate->add_option(opt_name, val);

    if (open_tables.empty())
    {
        DataApi::developer_error("Must open table before adding an option!!: " +
            opt_name + " = " + s_val);
        return false;
    }

    Table* t = open_tables.top();
    t->add_option(opt_name, val);
    return true;
}

bool TableApi::add_option(const std::string& val)
{
    if ( should_delegate() )
        return delegate->add_option(val);

    if (open_tables.empty())
    {
        DataApi::developer_error("Must open table before adding an option!!: "
            "<anonymous> = " + val);
        return false;
    }

    Table* t = open_tables.top();
    t->add_option(val);
    return true;
}

bool TableApi::add_option(const std::string& option_name, const std::string& val)
{ return do_add_option(option_name, val, val); }

bool TableApi::add_option(const std::string& option_name, const int val)
{ return do_add_option(option_name, val, std::to_string(val)); }

bool TableApi::add_option(const std::string& option_name, const bool val)
{ return do_add_option(option_name, val, std::to_string(val)); }

// compilers are fickle and dangerous creatures.  Ensure a literal gets
// sent here rather to become a bool
bool TableApi::add_option(const char* const v)
{ return add_option(std::string(v)); }

bool TableApi::add_option(const std::string& name, const char* const v)
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

template<typename T>
void TableApi::do_append_option(const std::string& option_name, const T val, const std::string& s_val)
{
    if ( should_delegate() )
    {
        delegate->append_option(option_name, val);
        return;
    }

    if (open_tables.empty())
    {
        DataApi::developer_error("Must open table before adding an option!!: " +
            option_name + " = " + s_val);
        return;
    }

    Table* t = nullptr;
    std::string opt_name(option_name);
    create_append_data(opt_name, t);

    if ( t != nullptr)
        t->append_option(opt_name, val);
    else
        DataApi::developer_error("Snort2lua cannot find a Table to append the option: "
            + option_name + " = " + s_val);
}

void TableApi::append_option(const std::string& option_name, const std::string& val)
{ do_append_option(option_name, val, val); }

void TableApi::append_option(const std::string& option_name, const int val)
{ do_append_option(option_name, val, std::to_string(val)); }

void TableApi::append_option(const std::string& option_name, const bool val)
{ do_append_option(option_name, val, std::to_string(val)); }

void TableApi::append_option(const std::string& name, const char* const v)
{ append_option(name, std::string(v)); }

bool TableApi::add_list(const std::string& list_name, const std::string& next_elem)
{
    if ( should_delegate() )
        return delegate->add_list(list_name, next_elem);

    if (open_tables.empty())
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

bool TableApi::add_comment(const std::string& comment)
{
    if ( should_delegate() )
        return delegate->add_comment(comment);

    if (open_tables.empty())
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

bool TableApi::option_exists(const std::string& name)
{
    if ( should_delegate() )
        return delegate->option_exists(name);

    if (open_tables.empty())
    {
        DataApi::developer_error("Must open table before calling option_exists() !!");
        return false;
    }

    return open_tables.top()->has_option(name);
}

bool TableApi::add_diff_option_comment(const std::string& orig_var, const std::string& new_var)
{
    if ( should_delegate() )
        return delegate->add_diff_option_comment(orig_var, new_var);

    std::string error_string = "option change: '" + orig_var + "' --> '"
        + new_var + "'";

    if (open_tables.empty())
    {
        DataApi::developer_error("Must open table before adding an option!!: " +
            orig_var + " = " + new_var);
        return false;
    }

    open_tables.top()->add_comment(error_string);
    return true;
}

bool TableApi::add_deleted_comment(const std::string& dep_var)
{
    if ( should_delegate() )
        return delegate->add_deleted_comment(dep_var);

    std::string error_string = "option deleted: '" + dep_var + "'";

    if (open_tables.empty())
    {
        DataApi::developer_error("Must open a table before adding "
            "deprecated comment!!: " + dep_var);
        return false;
    }

    open_tables.top()->add_comment(error_string);
    return true;
}

bool TableApi::add_unsupported_comment(const std::string& unsupported_var)
{
    if ( should_delegate() )
        return delegate->add_unsupported_comment(unsupported_var);

    std::string unsupported_str = "option '" + unsupported_var +
        "' is currently unsupported";

    if (open_tables.empty())
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
    table.print_tables(out);
    return out;
}

void TableApi::print_tables(std::ostream& out) const
{
    if ( empty() )
        return;

    for (Table* t : tables)
        out << (*t) << "\n\n";
}

void TableApi::swap_tables(std::vector<Table*>& new_tables)
{
    tables.swap(new_tables);
}

bool TableApi::get_option_value(const std::string& name, std::string& value)
{
    if ( should_delegate() )
        return delegate->get_option_value(name, value);

    if (open_tables.empty())
    {
        DataApi::developer_error("Must open table before calling option_exists() !!");
        return false;
    }

    return open_tables.top()->get_option(name, value);
}

void TableApi::run_when_exists(const char* table_name, PendingFunction action)
{
    if ( should_delegate(table_name) )
        delegate->run_when_exists(table_name, action);

    if ( util::find_table(tables, table_name) )
        action(*this);
    else
    {
        if ( pending.find(table_name) == pending.end() )
            pending[table_name] = std::queue<PendingFunction>();

        pending[table_name].push(action);
    }
}
