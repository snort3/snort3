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


bool Converter::convert_line(std::stringstream& data, std::ofstream& out)
{
    if ( state )
        return state->convert(data, out);
    return false;
}

bool Converter::open_table(std::string name)
{
    Table *t;

    // if no open tables, create a top-level table
    if (open_tables.size() > 0)
        t = open_tables.top()->open_table(name);
    else
        t = data.add_table(name);

    open_tables.push(t);
    return true;
}

bool Converter::close_table()
{
    open_tables.pop();
    return true;
}


bool Converter::add_option_to_table(std::string name, std::string val)
{
    Table *t = open_tables.top();

    if(t)
    {
        t->add_option(name, val);
        return true;
    }
    else
    {
        log_error("Must open table before adding an option!!");
        return false;
    }
}


bool Converter::add_option_to_table(std::string name, int val)
{
    Table *t = open_tables.top();

    if(t)
    {
        t->add_option(name, val);
        return true;
    }
    else
    {
        log_error("Must open table before adding an option!!");
        return false;
    }
}

bool Converter::add_option_to_table(std::string name, bool val)
{
    Table *t = open_tables.top();

    if(t)
    {
        t->add_option(name, val);
        return true;
    }
    else
    {
        log_error("Must open table before adding an option!!");
        return false;
    }
}


/*******************************
 *******  PRINTING FOO *********
 *******************************/

void Converter::log_error(std::string error_string)
{
    std::cout << "ERROR: Failed to convert:\t" << std::endl;
    std::cout << "\t\t" << error_string << std::endl << std::endl;
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
