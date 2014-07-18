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
// dt_data.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef DT_DATA_H
#define DT_DATA_H

#include <string>
#include <iostream>
#include <vector>
#include <stack>


#include "data/dt_table.h"
#include "data/dt_var.h"
#include "data/dt_comment.h"
#include "data/dt_rule.h"
#include "data/dt_include.h"

class LuaData
{

public:
    LuaData();
    virtual ~LuaData();

    // set the print mode. Quiet, Different, or Default. Setters for snort2lua,
    // getters are for other data classes.
    static inline void set_default_print() {mode = PrintMode::DEFAULT; }
    static inline bool is_default_mode() { return mode == PrintMode::DEFAULT; }
    static inline void set_quiet_print() {mode = PrintMode::QUIET; }
    static inline bool is_quiet_mode() { return mode == PrintMode::QUIET; }
    static inline void set_difference_print() {mode = PrintMode::DIFFERENCES; }
    static inline bool is_difference_mode() { return mode == PrintMode::DIFFERENCES; }
    inline bool failed_conversions() { return !errors->empty() || !bad_rules->empty(); }
    inline bool contains_rules() { return rules.size() != 0; }


    friend std::ostream &operator<<(std::ostream&, const LuaData &);
    void print_rules(std::ostream&, bool in_rule_file);
    void print_rejects(std::ostream&);
    void print_conf_options(std::ostream&);

    // functions specifically usefull when parsing includes.
    // allows for easy swapping of data.  These two functions
    // swap data which will be printed in 'print_rules()' and
    // 'print_conf_options()'
    void swap_rules(std::vector<Rule*>&);
    void swap_conf_data(std::vector<Variable*>&,
                            std::vector<Table*>&,
                            std::vector<Include*>&,
                            Comments*&);

    // FILE OUTPUTS

    void add_error_comment(std::string comment);
    // add a reject comment to the rejct file
    void add_comment(std::string comment);
    // add a variable to this file
    bool add_variable(std::string name, std::string value);
    // add a Snort style include file
    bool add_lua_file(std::string name);
    // add a Snort style include file
    bool add_include_file(std::string name);
    // reset any open tables.
    void reset_state();



    // TABLE OUTPUTS

    // open a table at the topmost layer. i.e., the table will not be nested inside any other table.
    void open_top_level_table(std::string name);
    // open a nested named table --> 'name = {...}')
    void open_table(std::string name);
    // create a new table with this name...even if a table with the same name already exists
    void open_new_top_level_table(std::string name);
    // open a nested table that does not contain a name --> {...})
    void open_table();
    // close the nested table.  go to previous table level
    void close_table();

    // ADDING FIELDS TO TABLES

    // add an string, bool, or int option to the table. --> table = { name = var };
    bool add_option_to_table(const std::string name, const std::string val);
    bool add_option_to_table(const std::string name, const int val);
    bool add_option_to_table(const std::string name, const bool val);
    bool add_option_to_table(const std::string name, const char* v);
    // add an option with a list of variables -->  table = { name = 'elem1 elem2 ...' }
    // corresponds to Parameter::PT_MULTI
    bool add_list_to_table(std::string list_name, std::string next_elem);
    // add a commment to be printed in the table --> table = { -- comment \n ... }
    bool add_comment_to_table(std::string comment);
    // add a comment about an option change to the table
    bool add_diff_option_comment(std::string orig_var, std::string new_var);
    // attach a deprecated option comment to the current table
    bool add_deleted_comment(std::string dep_var);
    // attach an unsupported option comment to the current table
    bool add_unsupported_comment(std::string unsupported_var);


    // RULE PARSING
    // Create a new rule object.
    void begin_rule();
    // Comment out the current rule
    void make_rule_a_comment();
    // bad rules...throw an error
    void bad_rule(std::string bad_option, std::istringstream& stream);
    // add a new peice of header_data to the current rule
    bool add_hdr_data(std::string data);
    // add a rule option (keyword and suboption)
    bool add_rule_option(std::string keyword);
    // add a rule option (keyword and suboption)
    bool add_rule_option(std::string keyword, std::string val);
    // add a rule option (keyword and suboption)
    bool add_rule_option_before_selected(std::string keyword, std::string val = std::string());
    // selects the rule option with the given name.  MUST BE CALLED BEFORE ADDING A SUBOPTION.
    bool select_option(std::string keyword);
    // clear the selected option.
    void unselect_option();
    // add a rule option (keyword and suboption)
    bool add_suboption(std::string keyword);
    // add a rule option (keyword and suboption)
    bool add_suboption(std::string keyword, std::string val, char delimeter);
    // add a comment to a rule
    void add_comment_to_rule(std::string coment);

private:
    enum class PrintMode
    {
        DEFAULT,
        DIFFERENCES,
        QUIET,
    };

    // actual configuration information
    static PrintMode mode;
    std::vector<Variable*> vars;
    std::vector<Table*> tables;
    std::vector<Rule*> rules;
    std::vector<Include*> includes;
    Comments* comments;
    Comments* errors;

    // various convenience pointers and holders
    std::stack<Table*> open_tables;
    Comments* bad_rules;
    Rule* curr_rule;
    RuleOption* curr_rule_opt;
    bool curr_rule_bad;

};



#endif
