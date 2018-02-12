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
// rule_urilen.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
namespace
{
class Urilen : public ConversionState
{
public:
    Urilen(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool Urilen::convert(std::istringstream& data_stream)
{
    std::string args;
    std::string value;

    args = util::get_rule_option_args(data_stream);

    size_t ltgt = args.find("<>");

    if ( ltgt != std::string::npos )
    {
        rule_api.add_comment("urilen: option change: '<>' --> '<=>'");
        args.insert(ltgt+1, "=");
    }
    std::istringstream arg_stream(args);

    // if there are no arguments, the option had a colon before a semicolon.
    // we are therefore done with this rule.
    if (util::get_string(arg_stream, value, ","))
    {
        rule_api.add_option("bufferlen", value);

        if (util::get_string(arg_stream, value, ","))
        {
            if (value == "raw")
                rule_api.set_curr_options_buffer("http_raw_uri");

            else if (value == "norm")
                rule_api.set_curr_options_buffer("http_uri");

            else
                rule_api.bad_rule(data_stream, "urilen:" + value + "," + args);
        }
        else
        {
            rule_api.set_curr_options_buffer("http_raw_uri");
        }
    }
    else
    {
        rule_api.bad_rule(data_stream, "urilen - option required");
    }

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

