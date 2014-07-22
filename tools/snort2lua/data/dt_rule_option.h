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
// dt_option.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef DT_RULE_OPTION_H
#define DT_RULE_OPTION_H

#include <string>
#include <vector>
#include <iostream>

#include "data/dt_rule_suboption.h"

class RuleOption
{
public:
    RuleOption(std::string name);
    RuleOption(std::string name, std::string val);
    virtual ~RuleOption();

    inline std::string get_name(){ return name; };

    bool add_suboption(std::string name);
    bool add_suboption(std::string name, std::string val, char delimeter);
 
    // overloading operators
    friend std::ostream &operator<<( std::ostream&, const RuleOption &);

private:

    std::string name;
    std::string value;
    std::vector<RuleSubOption*> sub_options;


};


#endif
