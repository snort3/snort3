//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "conversion_defines.h"
#include "data/dt_data.h"
#include "data/dt_rule_api.h"
#include "data/dt_table_api.h"
#include "helpers/util_binder.h"

typedef std::pair<unsigned, std::shared_ptr<Binder>> PendingBinder;


extern TableDelegation table_delegation;

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

    inline static void set_ips_pattern(const std::string& val)
    { ips_pattern = val; }

    inline static std::string get_ips_pattern()
    { return ips_pattern; }

    inline static void set_bind_wizard(bool val)
    { bind_wizard = val; }

    inline static bool get_bind_wizard()
    { return bind_wizard; }

    Binder& make_binder(Binder&);
    Binder& make_binder();
    Binder& make_pending_binder(int ips_policy_id);

    int convert(const std::string& input,
        const std::string& output,
        std::string rules,         // defaults to output_file
        std::string errors);         // defaults to output_file

    // parse a file without creating an entirely new Lua configuration
    int parse_include_file(const std::string& input_file);

    // set the next parsing state.
    void set_state(ConversionState* c, bool delete_old = true);
    // reset the current parsing state
    void reset_state();
    // parse an include file.  Use this function to ensure all options are set properly.
    int parse_file(const std::string& in_file, const std::string* out_file = nullptr,
        bool reset = true);

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

    bool added_ftp_data() const
    { return ftp_data_is_added; }

    void set_added_ftp_data()
    { ftp_data_is_added = true; }

private:
    static std::string ips_pattern;
    static bool parse_includes;
    static bool convert_rules_mult_files;
    static bool convert_conf_mult_files;
    static bool empty_args;
    static bool bind_wizard;

    bool ftp_data_is_added = false;

    DataApi data_api;

    // For the top-level file in an include chain.
    // If there a multiple snort 2 config items that create a particular table
    // then this must be used for handling that table to ensure one instance
    // of a table doesn't overwrite another when loaded
    TableApi top_table_api;

    // For the current file in an include chain
    TableApi table_api;

    RuleApi rule_api;
    std::vector<std::shared_ptr<Binder>> binders;
    std::vector<PendingBinder> pending_binders;

    // the current parsing state.
    ConversionState* state;
    bool error;
    bool multiline_state;

    // initialize data class
    bool initialize();

    void add_bindings();
};

#endif

