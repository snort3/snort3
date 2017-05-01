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
// dt_rule_api.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef DATA_DT_RULE_API_H
#define DATA_DT_RULE_API_H

#include <string>
#include <iostream>
#include <vector>
#include <stack>

class Rule;
class RuleOption;
class Comments;
class RuleApi;

// FIXIT-L simplify this API. Several options functions are no longer necessary

class RuleApi
{
public:
    RuleApi();
    virtual ~RuleApi();

    // miscellaneous
    static void set_remark(const char* s);
    bool failed_conversions() const;
    std::size_t num_errors() const;
    bool empty() const;
    void reset_state();

    friend std::ostream& operator<<(std::ostream&, const RuleApi&);
    void print_rules(std::ostream&, bool in_rule_file);
    void print_rejects(std::ostream&);

    // functions specifically useful when parsing includes.
    // allows for easy swapping of data.  These two functions
    // swap data which will be printed in 'print_rules()' and
    // 'print_conf_options()'
    void swap_rules(std::vector<Rule*>&); // FIXIT-L ?

    // include a snort-style rule file!
    void include_rule_file(std::string file_name);

    // Create a given rule
    void add_hdr_data(std::string data);
    void update_rule_action(std::string new_type);
    void add_option(std::string keyword);
    void add_option(std::string keyword, std::string val);
    void add_suboption(std::string keyword);
    void add_suboption(std::string keyword, std::string val);
    void set_curr_options_buffer(std::string buffer, bool add_option=false);

    void add_comment(std::string coment);
    void make_rule_a_comment();
    void bad_rule(std::istringstream& stream, std::string bad_option);

private:
    static std::size_t error_count;
    static std::string remark;

    std::vector<Rule*> rules;
    Comments* bad_rules;
    Rule* curr_rule;
    bool curr_data_bad;

    // Create a new rule object.
    void begin_rule();
};

#endif

