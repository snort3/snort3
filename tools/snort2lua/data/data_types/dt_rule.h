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
// dt_rule.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef DATA_DATA_TYPES_DT_RULE_H
#define DATA_DATA_TYPES_DT_RULE_H

#include <string>
#include <vector>
#include <iostream>
#include <array>

class RuleOption;

class Rule
{
public:
    Rule();
    virtual ~Rule();

    bool add_hdr_data(const std::string& data);
    void add_option(const std::string& keyword);
    void add_option(const std::string& keyword, const std::string& data);
    std::string get_option(const std::string& keyword);
    void update_option(const std::string& keyword, std::string& val);
    void add_suboption(const std::string& keyword);
    void add_suboption(const std::string& keyword, const std::string& val);
    void set_curr_options_buffer(const std::string& buffer, bool add_option);
    void update_rule_action(const std::string&);

    void add_comment(const std::string& comment);
    void bad_rule();
    void make_comment();
    void set_old_http_rule();
    bool is_old_http_rule() { return old_http_rule; }

    friend std::ostream& operator<<(std::ostream&, const Rule&);

private:
    std::vector<std::string> comments;
    std::array<std::string, 7> hdr_data;
    std::vector<RuleOption*> options;
    std::string sticky_buffer;
    std::size_t num_hdr_data;
    bool is_bad_rule;
    bool is_comment;
    bool old_http_rule;
};

#endif

