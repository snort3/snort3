/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// dt_rule_api.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef DATA_DT_RULE_API_H
#define DATA_DT_RULE_API_H

#include <string>
#include <iostream>
#include <vector>
#include <stack>

/*
 *
 * As a heads up to whoever reads this file.  This one API is
 * really three distinct API's rolled into one.  One API for rules,
 * one api for misc data (variables, includes, etcs), one api
 * for creating tables. Hoever, the reason they are
 * together is becasue this class is not static, and I did not
 * want to be pass three pointers to the three API's when
 * creating new convesion states.  There are comments in
 * in all caps which show the seperate the sections.
 *
 * The first section of this file is really DataApi creation
 * and initialization, and adding miscelaneous objects
 * to the DataApi data.  The second section is for creating
 * tables and their options.  The third section is for
 * creating rules.
 */

class Rule;
class RuleOption;
class Comments;
class RuleApi;


// Yes, I need to redo this API.

// FIXIT-L J  Simplify this API.  Several options functions are no longer necessary!!
class RuleApi
{

public:
    RuleApi();
    virtual ~RuleApi();


    bool failed_conversions() const;
    std::size_t num_errors() const;

    inline bool empty()
    { return rules.empty(); }

    friend std::ostream &operator<<(std::ostream&, const RuleApi &);
    void print_rules(std::ostream&, bool in_rule_file);
    void print_rejects(std::ostream&);

    // reset any open tables.
    void reset_state();

    // functions specifically usefull when parsing includes.
    // allows for easy swapping of data.  These two functions
    // swap data which will be printed in 'print_rules()' and
    // 'print_conf_options()'
    void swap_rules(std::vector<Rule*>&); // FIXIT ??


    // add a new peice of header_data to the current rule. Up to size allowed
    void add_hdr_data(std::string data);
    // Change the rule's action
    void update_rule_action(std::string new_type);
    // add a rule option (keyword and suboption)
    void add_option(std::string keyword);
    void add_option(std::string keyword, std::string val);
    // add a rule option (keyword and suboption)
    void add_suboption(std::string keyword);
    void add_suboption(std::string keyword, std::string val);
    // set the buffer for the last option which was set.
    void set_curr_options_buffer(std::string buffer);
    // add a comment to a rule
    void add_comment(std::string coment);
    // Comment out the current rule. Useful for deleted features where
    // rule should still be visible
    void make_rule_a_comment();
    // print this rule in the reject file.  Tell the user why this failed.
    void bad_rule(std::istringstream& stream, std::string bad_option);

private:
    std::vector<Rule*> rules;
    Comments* bad_rules;
    Rule* curr_rule;
    bool curr_data_bad;
    static std::size_t error_count;


    // Create a new rule object.
    void begin_rule();
};



#endif
