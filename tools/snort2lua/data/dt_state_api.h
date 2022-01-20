//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// dt_state_api.h author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifndef DATA_DT_STATE_API_H
#define DATA_DT_STATE_API_H

#include <iostream>
#include <vector>

class Rule;

class StateApi
{
public:
    StateApi() = default;
    ~StateApi() = default;

    void create_state();
    void clear();
    bool empty() const;
    void add_option(const std::string& keyword, const std::string& val);
    void add_deleted_comment(const std::string& option);
    void set_action(const std::string& action);
    void print_states(std::ostream& out) const;

private:
    std::vector<Rule*> states;
    Rule* curr_state = nullptr;
};

#endif

