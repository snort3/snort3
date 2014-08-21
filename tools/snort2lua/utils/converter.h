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
// converter.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef UTILS_CONVERTER_H
#define UTILS_CONVERTER_H

#include <string>
#include "conversion_defines.h"

class Converter;
extern Converter cv;

class Converter
{

public:
    Converter();
    virtual ~Converter();
    // initialize data class
    bool initialize(conv_new_f init_state_func);
    // set the next parsing state.
    void set_state(ConversionState* c);
    // tells this class whether to parse include files.
    inline void set_parse_includes(bool val) { parse_includes = val; }
    // tells this class whether to convert a file inline or pull all data into one file.
    inline void set_convert_rules_mult_files(bool var) { convert_rules_mult_files = var; }
    // tells this class whether to convert a file inline or pull all data into one file.
    inline void set_convert_conf_mult_files(bool var) { convert_conf_mult_files = var; }
    // reset the current parsing state
    void reset_state();
    // convert the following file from a snort.conf into a lua.conf
    int convert_file(std::string input_file);
    // parse an include file.  Use this function to ensure all set options are properly
    void parse_include_file(std::string file);
    // Should we parse an include file?
    inline bool should_convert_includes() { return parse_includes; }

private:
    // the current parsing state.
    ConversionState* state;
    // the data which will be printed into the new lua file
    // the init_state constructor
    conv_new_f init_state_ctor;

    bool parse_includes;
    bool convert_rules_mult_files;
    bool convert_conf_mult_files;
    bool error;

};



#endif
