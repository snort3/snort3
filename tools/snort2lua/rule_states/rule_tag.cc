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
// rule_tag.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
namespace
{
class Tag : public ConversionState
{
public:
    Tag(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool Tag::convert(std::istringstream& data_stream)
{
    std::string args;
    std::string value;
    std::string type;

    args = util::get_rule_option_args(data_stream);
    std::istringstream arg_stream(args);

    // if there are no arguments, the option had a colon before a semicolon.
    // we are therefore done with this rule.
    if (args.empty() || !util::get_string(arg_stream, value, " ,"))
    {
        rule_api.bad_rule(data_stream, "tag requires an argument!");
    }
    else
    {
        int seconds = 0;
        int bytes = 0;
        int packets = 0;
        bool is_host = false;
        bool valid = true;

        if (value == "host")
            is_host = true;

        else if (value == "session")
            is_host = false;

        else
        {
            valid = false;
            rule_api.bad_rule(data_stream, "tag type must be either 'host' or 'session'");
        }

        bool cnt = true;
        int opt_val = 0;

        while (util::get_string(arg_stream, value, " ,"))
        {
            if (cnt)
            {
                if (isdigit(value[0]))
                {
                    try
                    {
                        opt_val = std::stoi(value);
                    }
                    catch (std::exception &e)
                    {
                        rule_api.bad_rule(data_stream, "can't convert " + value + ":" + e.what());
                        valid = false;
                    }
                }
                else
                {
                    break;
                }
            }
            else
            {
                if (value == "seconds")
                    seconds = opt_val;

                else if (value == "bytes")
                    bytes = opt_val;

                else if (value == "packets")
                    packets = opt_val;

                else
                    rule_api.bad_rule(data_stream, "tag:<type> " + value + " - unknown metric");
            }
            cnt = !cnt;
        }

        if (is_host)
        {
            if (value == "src")
                type = "host_src";

            else if (value == "dst")
                type = "host_dst";

            else
            {
                rule_api.bad_rule(data_stream, "tag: ..." + value + " - must be src or dst");
                valid = false;
            }
        }
        else if (valid)
        {
            type = "session";

            if (value == "exclusive")
                rule_api.add_comment("tag: [,exclusive] is currently unsupported");
        }

        if (valid)
        {
            rule_api.add_option("tag", type);

            if (packets > 0)
                rule_api.add_suboption("packets", std::to_string(packets));

            if (seconds > 0)
                rule_api.add_suboption("seconds", std::to_string(seconds));

            if (bytes > 0)
                rule_api.add_suboption("bytes", std::to_string(bytes));
        }
    }

    return set_next_rule_state(data_stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& cv)
{ return new Tag(cv); }

static const ConvertMap tag_api =
{
    "tag",
    ctor,
};

const ConvertMap* tag_map = &tag_api;
} // namespace rules

