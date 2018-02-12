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
// dt_table.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "data/data_types/dt_table.h"
#include "data/dt_data.h"  // to check for print mode
#include "data/data_types/dt_option.h"
#include "data/data_types/dt_var.h"
#include "data/data_types/dt_comment.h"

static inline Table* find_table(std::vector<Table*> vec, const std::string& name)
{
    if (name.empty())
        return nullptr;

    for ( auto* t : vec)
        if (name == t->get_name())
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

Table::Table(const std::string& table_name, int d)
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

Table* Table::open_table(const std::string& table_name)
{
    Table* t = find_table(tables, table_name);

    if (t)
        return t;

    t = new Table(table_name, depth + 1);
    tables.push_back(t);
    return t;
}

bool Table::add_option(const std::string& value)
{
    Option* o = new Option(value, depth + 1);
    options.push_back(o);
    return true;
}

bool Table::add_option(const std::string& opt_name, int value)
{
    if (has_option(opt_name, value))
        return true;

    Option* o = new Option(opt_name, value, depth + 1);
    options.push_back(o);
    return true;
}

bool Table::add_option(const std::string& opt_name, bool value)
{
    if (has_option(opt_name, value))
        return true;

    Option* o = new Option(opt_name, value, depth + 1);
    options.push_back(o);
    return true;
}

bool Table::add_option(const std::string& opt_name, const std::string& value)
{
    if (has_option(opt_name, value))
        return true;

    Option* o = new Option(opt_name, value, depth + 1);
    options.push_back(o);
    return true;
}

void Table::append_option(const std::string& opt_name, int value)
{
    if (!has_option(opt_name, value))
    {
        Option* a = new Option(opt_name, value, 0);
        append_options.push_back(a);
    }
}

void Table::append_option(const std::string& opt_name, bool value)
{
    if (!has_option(opt_name, value))
    {
        Option* a = new Option(opt_name, value, 0);
        append_options.push_back(a);
    }
}

void Table::append_option(const std::string& opt_name, const std::string& value)
{
    if (!has_option(opt_name, value))
    {
        Option* a = new Option(opt_name, value, 0);
        append_options.push_back(a);
    }
}

bool Table::add_list(const std::string& list_name, const std::string& next_elem)
{
    for (auto l : lists)
        if (l->get_name() == list_name)
            return l->add_value(next_elem);

    Variable* var = new Variable(list_name, depth + 1);
    lists.push_back(var);
    return var->add_value(next_elem);
}

bool Table::has_option(const std::string& opt_name)
{
    for (Option* o : options)
        if (opt_name == o->get_name())
            return true;

    for (Option* a : append_options)
        if (opt_name == a->get_name())
            return true;

    return false;
}

bool Table::get_option(const std::string& opt_name, std::string& value)
{
    for (Option* o : options)
        if (opt_name == o->get_name())
        {
            value = o->get_value();
            return true;
        }

    for (Option* a : append_options)
        if (opt_name == a->get_name())
        {
            value = a->get_value();
            return true;
        }

    return false;
}

bool Table::has_option(const Option& opt)
{
    for (Option* o : options)
        if ( (*o) == opt)
            return true;

    for (Option* a : append_options)
        if ( (*a) == opt)
            return true;

    return false;
}

bool Table::has_option(const std::string& opt_name, int val)
{
    Option opt(opt_name, val, depth + 1);
    return has_option(opt);
}

bool Table::has_option(const std::string& opt_name, bool val)
{
    Option opt(opt_name, val, depth + 1);
    return has_option(opt);
}

bool Table::has_option(const std::string& opt_name, const std::string& val)
{
    Option opt(opt_name, val, depth + 1);
    return has_option(opt);
}

void Table::add_comment(const std::string& c)
{
    comments->add_sorted_text(c);
}

std::ostream& operator<<(std::ostream& out, const Table& t)
{
    std::string whitespace;

    for (int i = 0; i < t.depth; i++)
        whitespace += "    ";

    if (!t.name.empty())
    {
        if ( t.print_whitespace )
            out << whitespace;

        out << t.name << (t.one_line ? " = " : " =\n");
    }

    out << (t.print_whitespace ? whitespace : "")
        << (t.one_line ? "{ " : "{\n");

    // if we only want differences, don't print data
    if (!DataApi::is_difference_mode())
    {
        for (Option* o : t.options)
        {
            o->set_print_whitespace(!t.one_line);
            out << (*o) << (t.one_line ? ", " : ",\n");
        }

        for (Variable* v : t.lists)
        {
            v->set_print_whitespace(!t.one_line);
            out << (*v) << (t.one_line ? ", " : ",\n");
        }

        for (Table* sub_t : t.tables)
        {
            //If this table is one_lined, it may still print whitespace beforehand
            //Don't print whitespace within the table if it's one_lined
            sub_t->set_print_whitespace(!t.one_line);

            if ( t.one_line )
                sub_t->set_one_line(true);

            out << (*sub_t) << (t.one_line ? ", " : ",\n");
        }
    }
    else
    {
        for (Table* sub_t : t.tables)
        {
            if (sub_t->has_differences())
            {
                //If this table is one_lined, it may still print whitespace beforehand
                //Don't print whitespace within the table if it's one_lined
                sub_t->set_print_whitespace(!t.one_line);

                if ( t.one_line )
                    sub_t->set_one_line(true);

                out << (*sub_t) << (t.one_line ? ", " : ",\n");
            }
        }
    }


    if (!t.comments->empty() && !DataApi::is_quiet_mode())
    {
        // Comments need a new line regardless of one_line setting
        // When one_line is off, this section is already starting on it's own line
        if ( t.one_line )
            out << "\n";

        out << (*t.comments) << "\n";
    }

    if ( !t.one_line && t.print_whitespace )
        out << whitespace;
    out << "}";

    // Now, print all options which need to be appended/overwrite earlier options
    if (!t.append_options.empty())
    {
        if ( !t.one_line )
            out << "\n";

        for (Option* a : t.append_options)
        {
            a->set_print_whitespace(!t.one_line);

            out << (*a);
            if ( !t.one_line )
                out << "\n";
        }
    }

    return out;
}

