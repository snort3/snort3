//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
// dt_state_api.cc author Serhii Vlasiuk <svlasiuk@cisco.com>

#include "data/dt_state_api.h"

#include "data/data_types/dt_rule.h"

void StateApi::create_state()
{
    curr_state = new Rule();
    states.push_back(curr_state);
}

void StateApi::clear()
{
    for (auto s : states)
        delete s;

    states.clear();
}

bool StateApi::empty() const
{
    return states.empty();
}

void StateApi::set_action(const std::string& action)
{
    if ( curr_state )
        curr_state->add_hdr_data(action);
}

void StateApi::add_option(const std::string& name, const std::string& val)
{
    if ( curr_state )
        curr_state->add_option(name, val);
}

void StateApi::add_deleted_comment(const std::string& option)
{
    if ( curr_state )
    {
        std::string comment = "rule_state option '" + option + "' deleted";
        curr_state->add_comment(comment);
    }
}

void StateApi::print_states(std::ostream& out) const
{
    if ( states.empty() )
        return;

    out << "local_states =\n[[\n";

    for (const auto r : states)
        out << (*r) << "\n";

    out << "]]\n\n";
}

