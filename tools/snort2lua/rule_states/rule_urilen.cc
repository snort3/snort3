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
    Urilen(Converter& c) : ConversionState(c) {};
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
        retval = rule_api.add_rule_option("bufferlen", value);
        rule_api.select_option("bufferlen");

        if (util::get_string(arg_stream, value, ","))
        {
            bool tmpval = true;

            if (!value.compare("raw"))
                 rule_api.add_rule_option_before_selected("http_raw_uri");

            else if (!value.compare("norm"))
                 rule_api.add_rule_option_before_selected("http_uri");

            else
                rule_api.bad_rule(data_stream, "urilen:" + value + "," + args);
        }
        else
        {
            rule_api.add_rule_option_before_selected("http_uri");
        }
    }
    else
    {
        rule_api.bad_rule(data_stream, "urilen - option required");
    }

    rule_api.unselect_option();
    return set_next_rule_state(data_stream);
}

/**************************
 *******  A P I ***********
 **************************/


static ConversionState* ctor(Converter& c)
{
    return new Urilen(c);
}

static const std::string urilen = "urilen";
static const ConvertMap rule_urilen =
{
    "urilen",
    ctor,
};

const ConvertMap* urilen_map = &rule_urilen;

} // namespace rules
