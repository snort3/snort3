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
// converter.h author Josh Rosenbaum <jorosenba@cisco.com>

#ifndef CONVERTER_H
#define CONVERTER_H

#include <string>
#include <fstream>
#include <sstream>
#include <stack>

#include "data/cv_data.h"
#include "data/cv_var.h"

class ConversionState;

class Converter
{

public:
    Converter();
    virtual ~Converter() {};
    // convert the following line from a snort.conf into a lua.conf
    bool convert_line(std::stringstream& data);
    // set the next parsing state.
    void set_state(ConversionState* c);
    // reset the current parsing state
    void reset_state();
    // prints the entire lua configuration to the output file.
    friend std::ostream &operator<<( std::ostream& out, const Converter &cv) { return out << cv.data; }
    
    // add a variable to the new lua configuration. For example, --> HOME_NET = 'any'
    bool inline add_variable(std::string name, std::string v){ return data.add_variable(name, v); };

    // open a table that does not contain a name --> NOT 'name = {...}' ONLY {...})
    bool open_table();
    // open a  named tabled --> 'name = {...}')
    bool open_table(std::string name);
    // close the current table.  go to previous table level
    bool close_table();

    // add a string option to the table --> table = { name = 'val', }
    // corresponds to Parameter::PT_STRING, Parameter::PT_SELECT
    bool add_option_to_table(std::string name, std::string val);

    // add an int option to the table --> table = { name = val, }
    // corresponds to Parameter::PT_INT, Parametere::PT_PORT, Parametere::PT_REAL, etc
    bool add_option_to_table(std::string name, int val);
    
    // add a bool option to the table --> table = { name = true|false, }
    // corresponds to Parameter::PT_BOOL
    bool add_option_to_table(std::string name, bool val);
    
    // add an option with a list of variables -->  table = { name = 'elem1 elem2 ...' }
    // corresponds to Parameter::PT_MULTI
    bool add_list_to_table(std::string list_name, std::string next_elem);
    
    // add a commment to be printed in the table --> table = { -- comment \n ... }
    void add_comment_to_table(std::string comment);

    // comment will appear immediately below the lua configuration
    void add_comment_to_file(std::string comment);
    // add the entire stream as a comment in the new lua file
    void add_comment_to_file(std::string comment, std::stringstream& stream);
    // attach a comment about a deprecated option to a file or table
    void add_deprecated_comment(std::string dep_var);
    // add a comment with the formate 'deprecated option ... use the new option instead'
    void add_deprecated_comment(std::string dep_var, std::string new_var);
    // log an error in the new lua file
    void log_error(std::string);

    void print_line(std::stringstream& in);
    void print_line(std::ostringstream& in);
    void print_line(std::string& in);

private:
    // the current parsing state.
    ConversionState* state;
    // the data which will be printed into the new lua file
    ConversionData data;
    // keeps track of the current tables
    std::stack<Table*> open_tables;
};



#endif
