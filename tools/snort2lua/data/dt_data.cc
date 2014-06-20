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
#include "snort2lua_util.h"
#include <iostream>


static const std::string start_comments =
    "COMMENTS:\n"
    "    these line were originally commented out or empty"
    "in the configuration file.";


static inline Table* find_table(std::vector<Table*> vec, std::string name)
{
    if(name.empty())
        return nullptr;
    
    for( auto *t : vec)
        if(!name.compare(t->get_name()))
            return t;

    return nullptr;
}

ConversionData::ConversionData()
{
    comments = new Comments(start_comments, 0,
                    Comments::CommentType::Mult_Line);
}

ConversionData::~ConversionData()
{
    for (auto *v : vars)
        delete v;

    for (auto t : tables)
        delete t;

    delete comments;
}

bool ConversionData::add_variable(std::string name, std::string value)
{
    for (auto v : vars)
        if(v->get_name() == name)
            return v->add_value(value);

    Variable *var = new Variable(name);
    vars.push_back(var);
    return var->add_value(value);
}

Table* ConversionData::add_table(std::string name)
{
    Table* t = find_table(tables, name);

    if(t)
        return t;


    try
    {
        t = new Table(name, 0);
        tables.push_back(t);
        return t;
    }
    catch (std::bad_alloc& ba)
    {
        std::cout << "Failed to allocate memory for a new Table!!" << std::endl;
        exit (EXIT_FAILURE);
        return nullptr;
    }
}

void ConversionData::add_comment(std::string str)
{
    comments->add_text(str);
}

void ConversionData::add_error_comment(std::string error_string)
{
    if (error_string.size() > 80)
        error_string.insert(76, "...");
    
    errors.push_back(std::string(error_string, 0, 79));
}

std::ostream& operator<<( std::ostream &out, const ConversionData &data)
{
    out << "--[[" << std::endl;
    out << "--ERRORS:" << std::endl;
    out << "    all of these occured during the attempted conversion:" << std::endl << std::endl;

    for (std::string s : data.errors)
        out << s << std::endl << std::endl;

    out << "--]]" << std::endl << std::endl << std::endl;

    for (Variable *v : data.vars)
        out << (*v) << std::endl << std::endl;

    for (Table *t : data.tables)
        out << (*t) << std::endl << std::endl;

    out << (*data.comments) << std::endl;


    return out;
}
