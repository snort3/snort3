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
class Base64Decode : public ConversionState
{
public:
    Base64Decode(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool Base64Decode::convert(std::istringstream& data_stream)
{
    std::string args;
    std::string tmp;
    std::streamoff pos = data_stream.tellg();

    args = util::get_rule_option_args(data_stream);

    // if there are no arguments, the option had a colon before a semicolon.
    // we are therefore done with this rule.
    if (!args.empty())
    {
        // a colon will have been parsed when retrieving the keyword.
        // Therefore, if a colon is present, we are in the next rule option.
        if (args.find(':') != std::string::npos)
        {
            rule_api.add_option("base64_decode");
            data_stream.clear();
            data_stream.seekg(pos);
        }
        else
        {
            // since we still can't be sure if we passed the base64_decode buffer,
            // check the next option and ensure it matches
            std::istringstream arg_stream(args);
            util::get_string(arg_stream, tmp, ", ");

            if (tmp == "bytes" ||
                tmp == "offset" ||
                tmp == "relative")
            {
                rule_api.add_option("base64_decode", args);
            }
            else
            {
                data_stream.clear();
                data_stream.seekg(pos);
                rule_api.add_option("base64_decode");
            }
        }
    }
    return set_next_rule_state(data_stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& cv)
{
    return new Base64Decode(cv);
}

static const std::string base64_decode = "base64_decode";
static const ConvertMap base64_decode_api =
{
    base64_decode,
    ctor,
};

const ConvertMap* base64_decode_map = &base64_decode_api;
} // namespace rules

