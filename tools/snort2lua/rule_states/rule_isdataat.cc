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
// rule_isdataat.cc author Josh Rosenbaum <jrosenba@cisco.com>

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
class IsDataAt : public ConversionState
{
public:
    IsDataAt(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool IsDataAt::convert(std::istringstream& data_stream)
{
    std::string args;
    std::string value;

    args = util::get_rule_option_args(data_stream);
    std::istringstream arg_stream(args);

    // if there are no arguments, the option had a colon before a semicolon.
    // we are therefore done with this rule.
    if (args.empty() || !util::get_string(arg_stream, value, " ,"))
    {
        rule_api.bad_rule(data_stream, "isdataat requires an argument!");
    }
    else
    {
        rule_api.add_option("isdataat", value);

        while (util::get_string(arg_stream, value, " ,"))
        {
            if (value == "relative")
                rule_api.add_suboption("relative");

            else if (value == "rawbytes")
                rule_api.set_curr_options_buffer("pkt_data");

            else
                rule_api.bad_rule(data_stream, value + " - unknown modifier!!");
        }
    }

    return set_next_rule_state(data_stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& cv)
{ return new IsDataAt(cv); }

static const ConvertMap isdataat_api =
{
    "isdataat",
    ctor,
};

const ConvertMap* isdataat_map = &isdataat_api;
} // namespace rules

