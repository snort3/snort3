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
// rule_stream_size.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>
#include <cstdlib>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
namespace
{
class StreamSize : public ConversionState
{
public:
    StreamSize(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool StreamSize::convert(std::istringstream& data_stream)
{
    std::string args;

    args = util::get_rule_option_args(data_stream);
    std::istringstream arg_stream(args);

    std::string dir;
    std::string op;
    std::string size;

    if (!util::get_string(arg_stream, dir, ",") ||
        !util::get_string(arg_stream, op, ",") ||
        !util::get_string(arg_stream, size, ","))
    {
        rule_api.bad_rule(data_stream,
            "stream_size requires 3 arguments.  '<direction>,<operator>,<size>'");
        return set_next_rule_state(data_stream);
    }

    if (!(op == "=" || op == "<" || op == ">" || op == "!=" || op == "<=" || op == ">="))
    {
        rule_api.bad_rule(data_stream, "'" + op + "' in an invalid stream_size operator.");
    }

    try
    {
        // checking that this is a valid unsigned integer.
        char* end;
        std::strtoul(size.c_str(), &end, 10);
        rule_api.add_option("stream_size", op + size);
    }
    catch (const std::invalid_argument&)
    {
        rule_api.bad_rule(data_stream, "stream_size <size> '" + size + "' is too large.");
        rule_api.add_option("stream_size", op + size);
    }
    catch (const std::out_of_range&)
    {
        rule_api.bad_rule(data_stream, "stream_size <size> '" + size + "' is too large.");
        rule_api.add_option("stream_size", op + size);
    }

    if (dir == "either")
        rule_api.add_suboption("either");

    else if (dir == "both")
        rule_api.add_suboption("both");

    else if (dir == "client")
    {
        rule_api.add_suboption("to_server");

        static bool printed_client = false;
        if (!printed_client)
        {
            printed_client = true;
            rule_api.add_comment("stream_size: option change: 'client' --> 'to_server'");
        }
    }
    else if (dir == "server")
    {
        rule_api.add_suboption("to_client");

        static bool printed_server = false;
        if (!printed_server)
        {
            printed_server = true;
            rule_api.add_comment("stream_size: option change: 'server' --> 'to_client'");
        }
    }
    else
    {
        rule_api.bad_rule(data_stream, "stream_size: '" + dir + "' is invalid."
            "  Snort3.0 option ust be { either|to_server|to_client|both }");
    }

    return set_next_rule_state(data_stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* stream_size_ctor(Converter& c)
{ return new StreamSize(c); }

static const ConvertMap rule_stream_size =
{
    "stream_size",
    stream_size_ctor,
};

const ConvertMap* stream_size_map = &rule_stream_size;
} // namespace rules

