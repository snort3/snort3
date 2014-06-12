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

#include "data/conv_data.h"
#include "data/conv_var.h"

class ConversionState;

class Converter
{

public:
    Converter();
    virtual ~Converter() {};
    void reset_state();
    bool convert_line(std::stringstream& data);
    void set_state(ConversionState* c);
    
    bool inline add_variable(std::string name, std::string v){ return data.add_variable(name, v); };
    friend std::ostream &operator<<( std::ostream& out, const Converter &cv) { return out << cv.data; }

    // open a table that does not contain a name --> NOT 'name = {...}' ONLY {...})
    bool open_table();
    // open a  named tabled --> 'name = {...}')
    bool open_table(std::string name);
    // close the current table.  go to previous table level
    bool close_table();

    // add a string option to the table --> table = { name = 'val', }
    bool add_option_to_table(std::string name, std::string val);
    // add an int option to the table --> table = { name = val, }
    bool add_option_to_table(std::string name, int val);
    // add a bool option to the table --> table = { name = true|false, }
    bool add_option_to_table(std::string name, bool val);
    // add a commment to be printed in the table --> table = { -- comment \n }
    void add_comment_to_table(std::string comment);

    void add_comment_to_file(std::string comment);
    void add_comment_to_file(std::string comment, std::stringstream& stream);
    void log_error(std::string);

    void print_line(std::stringstream& in);
    void print_line(std::ostringstream& in);
    void print_line(std::string& in);

private:
    ConversionState* state;
    ConversionData data;
    std::stack<Table*> open_tables;


};



#endif
