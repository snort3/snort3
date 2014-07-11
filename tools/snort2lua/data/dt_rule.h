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
// dt_rule.h author Josh Rosenbaum <jorosenba@cisco.com>

#ifndef DT_RULE_H
#define DT_RULE_H


#include <string>
#include <vector>
#include <iostream>
#include <array>

#include "data/dt_rule_option.h"

class Rule
{
public:
    Rule();
    virtual ~Rule();

    bool add_hdr_data(std::string data);
    bool add_option(std::string keyword);
    bool add_option(std::string keyword, std::string data);
    RuleOption* select_option(std::string opt_name);
    bool add_option_before_selected(RuleOption* selected_opt,
                                    std::string keyword,
                                    std::string val);
    void add_comment(std::string comment);
    void bad_rule();
    void make_comment();

    friend std::ostream &operator<<( std::ostream&, const Rule &);

private:
    std::vector<std::string> comments;
    std::array<std::string, 7> hdr_data;
    std::vector<RuleOption*> options;
    std::size_t num_hdr_data;
    bool is_bad_rule;
    bool is_comment;
};

#endif
