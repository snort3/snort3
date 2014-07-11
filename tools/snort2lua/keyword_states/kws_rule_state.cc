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
// kws_rule_state.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "util/util.h"

namespace keywords
{

namespace {

class RuleState : public ConversionState
{
public:
    RuleState(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~RuleState() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool RuleState::convert(std::istringstream& data_stream)
{
    std::string arg;
    bool retval = true;
    int count = 0;

    ld->open_new_top_level_table("rule_state");

    while (util::get_string(data_stream, arg, ", "))
    {
        bool tmpval = true;

        switch (count)
        {
            case 0:
                tmpval = ld->add_option_to_table("sid", std::stoi(arg));
                count++;
                break;
            case 1:
                tmpval = ld->add_option_to_table("gid", std::stoi(arg));
                count++;
                break;
            case 2:
                if (!arg.compare("enabled"))
                {
                    ld->add_diff_option_comment("enabled", "enable");
                    tmpval = ld->add_option_to_table("enable", true);
                }
                else if (!arg.compare("disabled"))
                {
                    ld->add_diff_option_comment("disabled", "enable");
                    tmpval = ld->add_option_to_table("enable", false);
                }
                else
                {
                    ld->add_error_comment("unkown option!");
                    retval = false;
                }

                count++;
                break;
            case 3:
                ld->add_deprecated_comment("action");
                count++;
                break;
            default:
                ld->add_error_comment("rule_state has too many option!!");

        }

        if (retval && !tmpval)
            retval = false;
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new RuleState(cv, ld);
}

static const ConvertMap rule_state_api =
{
    "rule_state",
    ctor,
};

const ConvertMap* rule_state_map = &rule_state_api;

} // namespace keywords
