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
#include <iostream>
#include <istream>
#include <ostream>

#include "data/dt_data.h"
#include "data/dt_var.h"


// typedef redefined from 'conversion_state.h'
class ConversionState;
class Converter;
typedef ConversionState* (*conv_new_f)(Converter*, LuaData* ld);

class Converter
{

public:
    Converter();
    virtual ~Converter() {};
    // initialize data class
    bool initialize(conv_new_f init_state_func);
    // set the next parsing state.
    void set_state(ConversionState* c);
    // reset the current parsing state
    void reset_state();
    // convert the following file from a snort.conf into a lua.conf
    void convert_file(std::string input_file);
    // if the parse_include flag is set, parse this file.
    void parse_include_file(std::string input_file);
    // prints the entire lua configuration to the output file.
    friend std::ostream &operator<<( std::ostream& out, const Converter &cv) { return out << cv.ld; }
    


    // log an error in the new lua file
    void log_error(std::string);

    void print_line(std::istringstream& in);
    void print_line(std::ostringstream& in);
    void print_line(std::string& in);

private:
    // the current parsing state.
    ConversionState* state;
    // the data which will be printed into the new lua file
    LuaData ld;
    // the init_state constructor
    conv_new_f init_state_ctor;
    // parse_include_files
    bool parse_includes;

};



#endif
