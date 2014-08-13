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
// rule_urilen.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "rule_states/rule_api.h"
#include "utils/s2l_util.h"

namespace rules
{

namespace {


class Urilen : public ConversionState
{
public:
    Urilen(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~Urilen() {};
    virtual bool convert(std::istringstream& data);
};

} // namespace

bool Urilen::convert(std::istringstream& data_stream)
{
    std::string args;
    std::string value;
    bool retval = true;

    args = util::get_rule_option_args(data_stream);
    std::istringstream arg_stream(args);

    // if there are no arguments, the option had a colon before a semicolon.
    // we are therefore done with this rule.
    if (util::get_string(arg_stream, value, ","))
    {
        retval = ld->add_rule_option("urilen", value);
        ld->select_option("urilen");

        if (util::get_string(arg_stream, value, ","))
        {
            bool tmpval = true;

            if (!value.compare("raw"))
                tmpval = ld->add_rule_option_before_selected("http_raw_uri");

            else if (!value.compare("norm"))
                tmpval = ld->add_rule_option_before_selected("http_uri");

            else
                ld->bad_rule(data_stream, "invalid arguments: " + args);

            if (retval && !tmpval)
                retval = false;
        }
    }
    else
    {
        ld->bad_rule(data_stream, "urilen: option required");
    }

    ld->unselect_option();
    return set_next_rule_state(data_stream) && retval;
}

/**************************
 *******  A P I ***********
 **************************/


static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new Urilen(cv, ld);
}

static const std::string urilen = "urilen";
static const ConvertMap rule_urilen =
{
    "urilen",
    ctor,
};

const ConvertMap* urilen_map = &rule_urilen;

} // namespace rules
