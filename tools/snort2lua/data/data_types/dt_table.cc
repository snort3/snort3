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
// dt_table.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "data/data_types/dt_table.h"
#include "data/dt_data.h"  // to check for print mode
#include "data/data_types/dt_option.h"
#include "data/data_types/dt_var.h"
#include "data/data_types/dt_comment.h"

static inline Table* find_table(std::vector<Table*> vec, std::string name)
{
    if (name.empty())
        return nullptr;

    for ( auto* t : vec)
        if (!name.compare(t->get_name()))
            return t;

    return nullptr;
}

Table::Table(int d)
{
    this->name = "";
    this->depth = d;
    this->comments = new Comments(d + 1,
        Comments::CommentType::SINGLE_LINE);
}

Table::Table(std::string table_name, int d)
{
    this->name = table_name;
    this->depth = d;
    this->comments = new Comments(d + 1,
        Comments::CommentType::SINGLE_LINE);
}

Table::~Table()
{
    for ( Table* t : tables)
        delete t;

    for ( Option* o : options)
        delete o;

    for ( Variable* l: lists )
        delete l;

    for ( Option* a : append_options)
        delete a;

    delete comments;
}

bool Table::has_differences()
{
    if (!comments->empty())
        return true;

    for (Table* t : tables)
        if (t->has_differences())
            return true;

    return false;
}

Table* Table::open_table()
{
    Table* t = new Table(depth + 1);
    tables.push_back(t);
    return t;
}

Table* Table::open_table(std::string table_name)
{
    Table* t = find_table(tables, table_name);

    if (t)
        return t;

    t = new Table(table_name, depth + 1);
    tables.push_back(t);
    return t;
}

bool Table::add_option(std::string value)
{
    Option* o = new Option(value, depth + 1);
    options.push_back(o);
    return true;
}

bool Table::add_option(std::string opt_name, int value)
{
    if (has_option(opt_name, value))
        return true;

    Option* o = new Option(opt_name, value, depth + 1);
    options.push_back(o);
    return true;
}

bool Table::add_option(std::string opt_name, bool value)
{
    if (has_option(opt_name, value))
        return true;

    Option* o = new Option(opt_name, value, depth + 1);
    options.push_back(o);
    return true;
}

bool Table::add_option(std::string opt_name, std::string value)
{
    if (has_option(opt_name, value))
        return true;

    Option* o = new Option(opt_name, value, depth + 1);
    options.push_back(o);
    return true;
}

void Table::append_option(std::string opt_name, int value)
{
    if (!has_option(opt_name, value))
    {
        Option* a = new Option(opt_name, value, 0);
        append_options.push_back(a);
    }
}

void Table::append_option(std::string opt_name, bool value)
{
    if (!has_option(opt_name, value))
    {
        Option* a = new Option(opt_name, value, 0);
        append_options.push_back(a);
    }
}

void Table::append_option(std::string opt_name, std::string value)
{
    if (!has_option(opt_name, value))
    {
        Option* a = new Option(opt_name, value, 0);
        append_options.push_back(a);
    }
}

bool Table::add_list(std::string list_name, std::string next_elem)
{
    for (auto l : lists)
        if (l->get_name() == list_name)
            return l->add_value(next_elem);

    Variable* var = new Variable(list_name, depth + 1);
    lists.push_back(var);
    return var->add_value(next_elem);
}

bool Table::has_option(const std::string opt_name)
{
    for (Option* o : options)
        if (!opt_name.compare(o->get_name()))
            return true;

    for (Option* a : append_options)
        if (!opt_name.compare(a->get_name()))
            return true;

    return false;
}

bool Table::get_option(const std::string opt_name, std::string& value)
{
    for (Option* o : options)
        if (!opt_name.compare(o->get_name()))
        {
            value = o->get_value();
            return true;
        }

    for (Option* a : append_options)
        if (!opt_name.compare(a->get_name()))
        {
            value = a->get_value();
            return true;
        }

    return false;
}

bool Table::has_option(Option opt)
{
    for (Option* o : options)
        if ( (*o) == opt)
            return true;

    for (Option* a : append_options)
        if ( (*a) == opt)
            return true;

    return false;
}

bool Table::has_option(std::string opt_name, int val)
{
    Option opt(opt_name, val, depth + 1);
    return has_option(opt);
}

bool Table::has_option(std::string opt_name, bool val)
{
    Option opt(opt_name, val, depth + 1);
    return has_option(opt);
}

bool Table::has_option(std::string opt_name, std::string val)
{
    Option opt(opt_name, val, depth + 1);
    return has_option(opt);
}

void Table::add_comment(std::string c)
{
    comments->add_sorted_text(c);
}

std::ostream& operator<<(std::ostream& out, const Table& t)
{
    std::string whitespace = "";

    for (int i = 0; i < t.depth; i++)
        whitespace += "    ";

    if (!t.name.empty())
        out << whitespace << t.name << " =" << std::endl;
    out << whitespace << '{' << std::endl;

    if (!t.comments->empty() && !DataApi::is_quiet_mode())
        out << (*t.comments) << std::endl;

    // if we only want differences, don't print data
    if (!DataApi::is_difference_mode())
    {
        for (Option* o : t.options)
            out << (*o) << ",\n";

        for (Variable* v : t.lists)
            out << (*v) << ",\n";

        for (Table* sub_t : t.tables)
            out << (*sub_t) << ",\n";
    }
    else
    {
        for (Table* sub_t : t.tables)
            if (sub_t->has_differences())
                out << (*sub_t) << ",\n";
    }

    out << whitespace << "}";

    // Now, print all options which need to be appended/overwrite earlier options
    if (!t.append_options.empty())
    {
        out << "\n";

        for (Option* a : t.append_options)
            out << (*a) << "\n";
    }

    return out;
}

