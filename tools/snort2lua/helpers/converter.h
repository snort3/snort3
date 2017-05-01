//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// converter.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef UTILS_CONVERTER_H
#define UTILS_CONVERTER_H

#include <string>
#include "conversion_defines.h"
#include "data/dt_data.h"
#include "data/dt_table_api.h"
#include "data/dt_rule_api.h"

class Converter
{
public:
    Converter();
    virtual ~Converter();

    // tells this class whether to parse include files.
    inline static void set_parse_includes(bool val)
    { parse_includes = val; }

    inline static bool get_parse_includes()
    { return parse_includes; }

    // tells this class whether to convert a file inline or pull all data into one file.
    inline static void create_mult_rule_files(bool var)
    { convert_rules_mult_files = var; }

    inline static bool include_create_rule()
    { return convert_rules_mult_files; }

    // tells this class whether to convert a file inline or pull all data into one file.
    inline static void create_mult_conf_files(bool var)
    { convert_conf_mult_files = var; }

    inline static bool include_create_lua()
    { return convert_conf_mult_files; }

    inline static void set_empty_args(bool val)
    { empty_args = val; }

    int convert(std::string input,
        std::string output,
        std::string rules,         // defaults to output_file
        std::string errors);         // defaults to output_file

    // parse a file without creating an entirely new Lua configuration
    int parse_include_file(std::string input_file);

    // set the next parsing state.
    void set_state(ConversionState* c);
    // reset the current parsing state
    void reset_state();
    // parse an include file.  Use this function to ensure all set options are properly
    int parse_file(std::string file);

    bool failed_conversions() const
    { return data_api.failed_conversions() || rule_api.failed_conversions(); }

    inline void start_multiline_parsing()
    { multiline_state = true; }

    inline void end_multiline_parsing()
    { multiline_state = false; }

    inline DataApi& get_data_api()
    { return data_api; }

    inline TableApi& get_table_api()
    { return table_api; }

    inline RuleApi& get_rule_api()
    { return rule_api; }

private:
    static bool parse_includes;
    static bool convert_rules_mult_files;
    static bool convert_conf_mult_files;
    static bool empty_args;

    DataApi data_api;
    TableApi table_api;
    RuleApi rule_api;

    // the current parsing state.
    ConversionState* state;
    bool error;
    bool multiline_state;

    // initialize data class
    bool initialize();
};

#endif

