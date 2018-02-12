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
// rule_base64_decode.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
namespace
{
class Ttl : public ConversionState
{
public:
    Ttl(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream&) override;
};
} // namespace

bool Ttl::convert(std::istringstream& stream)
{
    std::string arg = util::get_rule_option_args(stream);

    if ( arg.empty() )
    {
        rule_api.bad_rule(stream, "ttl <missing_arg>");
    }
    else
    {
        std::string new_val;

        if ( arg.find('-') == std::string::npos )
            new_val = arg;
        else
        {
            if ( arg.find('-') != arg.rfind('-') )
            {
                new_val = arg;
                rule_api.bad_rule(stream, "ttl '" + arg + "'' contains "
                    "multiple dashes");
            }
            else
            {
                if ( arg.front() == '-' )
                {
                    arg.erase(0, 1);
                    new_val = "<=" + arg;
                }
                else if ( arg.back() == '-' )
                {
                    arg.pop_back();
                    new_val = ">=" + arg;
                }
                else
                {
                    std::istringstream arg_stream(arg);
                    int low;
                    int high;

                    arg_stream >> low;
                    arg_stream.ignore(1);
                    arg_stream >> high;
                    new_val = std::to_string(low) + "<=>" + std::to_string(high);
                }
            }
        }

        rule_api.add_option("ttl", new_val);
    }

    return set_next_rule_state(stream);
}

static ConversionState* ctor(Converter& c)
{ return new Ttl(c); }

static const ConvertMap rule_ttl =
{
    "ttl",
    ctor,
};

const ConvertMap* ttl_map = &rule_ttl;
} // namespace rules

