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
// conv_data.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include "conv_data.h"
#include "snort2lua_util.h"

#if 0
    std::vector<Variable> vars;
    std::vector<Table> tables;
    Table curr_table;
#endif


static inline Table* find_table(std::vector<Table*> vec, std::string name)
{
    for( auto *t : vec)
        if(name.compare(t->get_name()))
            return t;

    return nullptr;
}

ConversionData::ConversionData()
{
}

ConversionData::~ConversionData()
{
    for (auto *v : vars)
        delete v;

    for (auto t : tables)
        delete t;
}

std::ostream& operator<<( std::ostream &out, const ConversionData &data)
{
    for (Variable *v : data.vars)
        out << (*v) << std::endl << std::endl;

    for (Table *t : data.tables)
        out << (*t) << std::endl << std::endl;

    return out;
}

bool ConversionData::add_variable(std::string name, std::string value)
{
    for (auto v : vars)
    {
        if(v->get_name() == name)
        {
            return v->add_value(value);
        }
    }

    Variable *var = new Variable(name);
    vars.push_back(var);
    return var->add_value(value);
}


Table* ConversionData::add_table(std::string name)
{
    Table* t = find_table(tables, name);

    if(t)
        return t;

    t = new Table(name, 0);
    tables.push_back(t);
    return t;
}

#if 0
bool ConversionData::add_option(std::string name, std::string value)
{

}

bool ConversionData::add_option(std::string name, long long int value)
{

}


void ConversionData::reset()
{

}

#endif
