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
// dt_table.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include "data/dt_table.h"

static inline Table* find_table(std::vector<Table*> vec, std::string name)
{
    if(name.empty())
        return nullptr;

    for( auto *t : vec)
        if(!name.compare(t->get_name()))
            return t;

    return nullptr;
}

Table::Table(int depth)
{
    this->name = "";
    this->depth = depth;
    this->comments = new Comments(depth + 1,
                    Comments::CommentType::SINGLE_LINE);
}

Table::Table(std::string name, int depth)
{
    this->name = name;
    this->depth = depth;
    this->comments = new Comments(depth + 1,
                    Comments::CommentType::SINGLE_LINE);
}

Table::~Table()
{
    for( Table* t : tables)
        delete t;

    for( Option* o : options)
        delete o;

    delete comments;
}

Table* Table::open_table()
{
    Table *t = new Table(depth + 1);
    tables.push_back(t);
    return t;
}

Table* Table::open_table(std::string name)
{
    Table* t = find_table(tables, name);

    if(t)
        return t;

    t = new Table(name, depth + 1);
    tables.push_back(t);
    return t;
}

bool Table::add_option(std::string name, int value)
{
    if (has_option(name, value))
        return true;

    Option *o = new Option(name, value, depth + 1);
    options.push_back(o);
    return true;
}

bool Table::add_option(std::string name, bool value)
{
    if (has_option(name, value))
        return true;

    Option *o = new Option(name, value, depth + 1);
    options.push_back(o);
    return true;
}

bool Table::add_option(std::string name, std::string value)
{
    if (has_option(name, value))
        return true;

    Option *o = new Option(name, value, depth + 1);
    options.push_back(o);
    return true;
}


bool Table::add_list(std::string name, std::string next_elem)
{
    for (auto l : lists)
        if(l->get_name() == name)
            return l->add_value(next_elem);

    Variable *var = new Variable(name, depth + 1);
    lists.push_back(var);
    return var->add_value(next_elem);
}

bool Table::has_option(Option opt)
{
    for (Option* o : options)
        if ( (*o) == opt)
            return true;

    return false;
}

bool Table::has_option(std::string name, int val)
{
    Option opt(name, val, depth + 1);
    return has_option(opt);
}

bool Table::has_option(std::string name, bool val)
{
    Option opt(name, val, depth + 1);
    return has_option(opt);
}

bool Table::has_option(std::string name, std::string val)
{
    Option opt(name, val, depth + 1);
    return has_option(opt);
}


void Table::add_comment(std::string c)
{
    comments->add_text(c);
}

std::ostream &operator<<( std::ostream& out, const Table &t)
{
    std::string whitespace = "";

    for(int i = 0; i < t.depth; i++)
        whitespace += "    ";

    if(!t.name.empty())
        out << whitespace << t.name << " = " << std::endl;
    out << whitespace << '{' << std::endl;

    if (!t.comments->empty())
        out << (*t.comments) << std::endl;

    for (Option* o : t.options)
        out << (*o) << ',' << std::endl;

    for (Variable* v : t.lists)
        out << (*v) << ',' << std::endl;

    for (Table* sub_t : t.tables)
        out << (*sub_t) << ',' << std::endl;

    // don't add a comma if the depth is zero
    if(t.depth == 0)
        out << "}";
    else
        out << whitespace << "}";
    
    return out;
}
