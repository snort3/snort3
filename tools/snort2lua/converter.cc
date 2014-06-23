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
// converter.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <iostream>
#include "converter.h"
#include "conversion_state.h"
#include "init_state.h"

#if 0
Converter::Converter(Converter* c)
{
    state = c;    
}

Converter::~Converter(){} 
#endif
Converter::Converter()
{
    state = nullptr;
}

void Converter::set_state(ConversionState* c)
{
    delete state;
    state = c;
}

void Converter::reset_state()
{
    if (state)
        delete state;

    state = new InitState(this);

    std::stack<Table*> empty;
    open_tables.swap(empty );
}


bool Converter::convert_line(std::stringstream& data)
{
    if ( state )
        return state->convert(data);
    return false;
}

bool Converter::open_table()
{
    // if no open tables, create a top-level table
    if (open_tables.size() > 0)
    {
        Table *t = open_tables.top()->open_table();
        open_tables.push(t);
        return true;
    }
    else
    {
        log_error("A nameless table must be nested!!");
        return false;
    }
}

bool Converter::open_table(std::string table_name)
{
    Table *t;

    // if no open tables, create a top-level table
    if (open_tables.size() > 0)
        t = open_tables.top()->open_table(table_name);
    else
        t = data.add_table(table_name);

    open_tables.push(t);
    return true;
}

bool Converter::open_top_level_table(std::string table_name)
{
    Table *t = data.add_table(table_name);
    open_tables.push(t);
    return true;
}

bool Converter::close_table()
{
    open_tables.pop();
    return true;
}


bool Converter::add_option_to_table(std::string option_name, std::string val)
{
    if(open_tables.size() == 0)
    {
        log_error("Must open table before adding an option!!: " +
            option_name + " = " + val);
        return false;
    }

    Table *t = open_tables.top();
    t->add_option(option_name, val);
    return true;
}


bool Converter::add_option_to_table(std::string option_name, int val)
{
    if(open_tables.size() == 0)
    {

        log_error("Must open table before adding an option!!: " +
            option_name + " = " + std::to_string(val));
        return false;
    }

    Table *t = open_tables.top();
    t->add_option(option_name, val);
    return true;
}

bool Converter::add_option_to_table(std::string option_name, bool val)
{
    if(open_tables.size() == 0)
    {
        log_error("Must open table before adding an option!!: " +
            option_name + " = " + std::to_string(val));
        return false;
    }

    Table *t = open_tables.top();
    t->add_option(option_name, val);
    return true;
}


bool Converter::add_list_to_table(std::string list_name, std::string next_elem)
{
    if(open_tables.size() == 0)
    {
        log_error("Must open table before adding an option!!: " +
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
        log_error("Must open table before adding an list!!: " +
            list_name + " += " + next_elem);
        return false;
    }
}

void Converter::add_comment_to_table(std::string error_string)
{
    if (open_tables.size() > 0)
        open_tables.top()->add_comment(error_string);
    else
        log_error(error_string);
}

void Converter::add_comment_to_file(std::string comment)
{
    data.add_comment(comment);
}

void Converter::add_comment_to_file(std::string comment, std::stringstream& stream)
{
    int pos = stream.tellg();
    std::ostringstream oss;
    oss << stream.rdbuf();
    comment += oss.str();
    data.add_comment(comment);
    stream.seekg(pos);
}

void Converter::add_deprecated_comment(std::string dep_var)
{
    std::string error_string = "option deprecated: '" + dep_var + "'";

    if (open_tables.size() > 0)
        add_comment_to_table(error_string);
    else
        add_comment_to_file(error_string);
}

void Converter::add_diff_option_comment(std::string dep_var, std::string new_var)
{
    std::string error_string = "option change: '" + dep_var + "' --> '"
            + new_var + "'";

    if (open_tables.size() > 0)
        add_comment_to_table(error_string);
    else
        add_comment_to_file(error_string);
}

/*******************************
 *******  PRINTING FOO *********
 *******************************/

void Converter::log_error(std::string error_string)
{
    data.add_error_comment(error_string);
//    std::cout << "ERROR: Failed to convert:\t" << std::endl;
//    std::cout << "\t\t" << error_string << std::endl << std::endl;
}

void Converter::print_line(std::stringstream& in)
{
    int pos = in.tellg();
    std::ostringstream oss;
    oss << in.rdbuf();
    std::cout << "DEBUG: " << oss.str() << std::endl;
    in.seekg(pos);
}

void Converter::print_line(std::ostringstream& in)
{
    std::cout << "DEBUG: " << in.str() << std::endl;
}
void Converter::print_line(std::string& in)
{
    std::cout << "DEBUG: " << in << std::endl;
}

#if 0

void Converter::inititalize()
{
		state = this;
}



void Converter::set_state(Converter* c){ 
    delete state;
    state = c; 
}

#endif
