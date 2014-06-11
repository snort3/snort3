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
// conv_table.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include "data/conv_table.h"

static inline Table* find_table(std::vector<Table*> vec, std::string name)
{
    for( auto *t : vec)
        if(name.compare(t->get_name()))
            return t;

    return nullptr;
}

Table::Table(std::string name)
{
    this->name = name;
    depth = 0;
}

Table::Table(std::string name, int depth)
{
    this->name = name;
    this->depth = depth;
}

Table::~Table()
{
    for( Table* t : tables)
        delete t;

    for( Option* o : options)
        delete o;
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
    Option *o = new Option(name, value, depth + 1);
    options.push_back(o);
    return true;
}

bool Table::add_option(std::string name, bool value)
{
    Option *o = new Option(name, value, depth + 1);
    options.push_back(o);
    return true;
}

bool Table::add_option(std::string name, std::string value)
{
    Option *o = new Option(name, value, depth + 1);
    options.push_back(o);
    return true;
}

bool Table::has_option(std::string name, int val)
{
    Option new_opt(name, val, depth + 1);

    for (Option* o : options)
        if ( *o == new_opt)
            return true;

    return false;
}

bool Table::has_option(std::string name, bool val)
{
    return false;
}

bool Table::has_option(std::string name, std::string val)
{
    Option new_opt(name, val, depth+1);

    for (Option* o : options)
        if ( *o == new_opt)
            return true;

    return false;
}

std::ostream &operator<<( std::ostream& out, const Table &t)
{
    std::string whitespace = "";

    for(int i = 0; i < t.depth; i++)
        whitespace += "    ";

    out << whitespace << t.name << " = " << std::endl;
    out << whitespace << '{' << std::endl;

    for (Option* o : t.options)
        out << (*o) << std::endl;

    for (Table* t : t.tables)
        out << (*t) << std::endl;

    // don't add a comma if the depth is zero
    if(t.depth == 0)
        out << "}";
    else
        out << whitespace << "},";
    
    return out;
}
