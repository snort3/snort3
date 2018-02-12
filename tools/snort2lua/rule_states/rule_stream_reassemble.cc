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
class StreamReassemble : public ConversionState
{
public:
    StreamReassemble(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool StreamReassemble::convert(std::istringstream& data_stream)
{
    std::string args;
    std::string action;
    std::string direction;

    args = util::get_rule_option_args(data_stream);
    std::istringstream arg_stream(args);

    // if there are no arguments, the option had a colon before a semicolon.
    // we are therefore done with this rule.
    if (args.empty() ||
        !util::get_string(arg_stream, action, ",") ||
        !util::get_string(arg_stream, direction, ","))
    {
        rule_api.bad_rule(data_stream, "stream_reassemble requires two arguments!");
        return set_next_rule_state(data_stream);
    }

    if ( action != "enable" && action != "disable" )
    {
        rule_api.bad_rule(data_stream, "stream_reassemble: " +
            action + " must be either 'enable' or 'disable'");
    }

    if (direction != "client" &&
        direction != "server" &&
        direction != "both" )
    {
        rule_api.bad_rule(data_stream, "stream_reassemble: " +
            direction + " must be either 'client', 'server', or 'both'");
    }

    rule_api.add_option("stream_reassemble");
    rule_api.add_suboption("action", action);
    rule_api.add_suboption("direction", direction);

    int cnt = 0;
    std::string keyword;
    while ( util::get_string(arg_stream, keyword, ",") )
    {
        if (keyword == "noalert")
            rule_api.add_suboption("noalert");

        else if (keyword == "fastpath")
            rule_api.add_suboption("fastpath");

        else
            rule_api.bad_rule(data_stream, "stream_reassemble: " + keyword);

        if (++cnt > 2)
            rule_api.bad_rule(data_stream, "stream_reassemble: "
                "only four options allowed.");
    }

    return set_next_rule_state(data_stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& cv)
{ return new StreamReassemble(cv); }

static const ConvertMap stream_reassemble_api =
{
    "stream_reassemble",
    ctor,
};

const ConvertMap* stream_reassemble_map = &stream_reassemble_api;
} // namespace rules

