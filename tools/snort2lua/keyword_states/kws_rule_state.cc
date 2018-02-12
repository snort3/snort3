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

bool RuleState::convert(std::istringstream& data_stream)
{
    std::string arg;
    bool retval = true;
    int count = 0;

    table_api.open_table("rule_state");
    table_api.open_table();

    while (util::get_string(data_stream, arg, ", "))
    {
        switch (count)
        {
        case 0:
            table_api.add_option("sid", std::stoi(arg));
            count++;
            break;
        case 1:
            table_api.add_option("gid", std::stoi(arg));
            count++;
            break;
        case 2:
            if (arg == "enabled")
            {
                table_api.add_diff_option_comment("enabled", "enable");
                table_api.add_option("enable", true);
            }
            else if (arg == "disabled")
            {
                table_api.add_diff_option_comment("disabled", "enable");
                table_api.add_option("enable", false);
            }
            else
            {
                data_api.failed_conversion(data_stream, "third option must be {enabled|disabled|");
                retval = false;
            }

            count++;
            break;
        case 3:
            table_api.add_deleted_comment("action");
            count++;
            break;
        default:
            retval = false;
            data_api.failed_conversion(data_stream, "too many options! - " + arg);
        }
    }

    table_api.close_table();
    table_api.close_table();
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

