//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
// kws_rule_state.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace keywords
{
namespace
{
class RuleState : public ConversionState
{
public:
    RuleState(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

using namespace std;

bool RuleState::convert(std::istringstream& data_stream)
{
    static bool did_preamble = false;

    std::string arg;
    bool retval = true;
    int count = 0;

    if ( !did_preamble )
    {
        did_preamble = true;
        table_api.open_table("detection");
        table_api.add_option("global_rule_state", true);
        table_api.close_table();
    }

    string gid;
    string sid;
    string enable;
    string action;

    while (util::get_string(data_stream, arg, ", "))
    {
        switch (count)
        {
        case 0:
            sid = arg;
            count++;
            break;
        case 1:
            gid = arg;
            count++;
            break;
        case 2:
            if (arg == "enabled")
                enable = "yes";
            else if (arg == "disabled")
                enable = "no";
            else
            {
                data_api.failed_conversion(data_stream, "third option must be {enabled|disabled|");
                retval = false;
            }

            count++;
            break;
        case 3:
            action = arg;
            count++;
            break;
        default:
            retval = false;
            data_api.failed_conversion(data_stream, "too many options! - " + arg);
        }
    }

    if ( count < 2 )
    {
        data_api.failed_conversion(data_stream, "must set a gid and sid for rule state" + arg);
        retval = false;
    }

    if ( retval )
    {
        state_api.create_state();
        state_api.add_option("gid", gid);
        state_api.add_option("sid", sid);

        if ( !enable.empty() )
        {
            state_api.add_option("enable", enable);
            state_api.add_deleted_comment("enable");
        }

        if ( !action.empty() )
        {
            if ( action == "sdrop" )
            {
                action = "drop";
                state_api.add_deleted_comment("action");
            }

            state_api.set_action(action);
        }
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new RuleState(c); }

static const ConvertMap rule_state_api =
{
    "rule_state",
    ctor,
};

const ConvertMap* rule_state_map = &rule_state_api;
} // namespace keywords

