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
// rule_base64_decode.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "rule_states/rule_api.h"
#include "util/util.h"

namespace rules
{

namespace {


class Base64Decode : public ConversionState
{
public:
    Base64Decode(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~Base64Decode() {};
    virtual bool convert(std::istringstream& data);
};

} // namespace

bool Base64Decode::convert(std::istringstream& data_stream)
{
    std::string args;
    std::string tmp;
    int pos = data_stream.tellg();
    bool retval;

    // a colon should have already been parsed when retrieving the keyword.
    // Therefore, if a semicolon is present, we are in the next rule option.
    args = util::get_rule_option_args(data_stream);
    if (args.find(":") != std::string::npos)
    {
        retval = ld->add_rule_option("base64_decode");
        data_stream.seekg(pos);
        return set_next_rule_state(data_stream);
    }

    // since we still can't be sure if we passed the base64_decode buffer,
    // check the next option and ensure it matches
    std::istringstream(args) >> tmp;
    if (!tmp.compare("bytes") ||
        !tmp.compare("offset") ||
        !tmp.compare("relative"))
    {
        retval = ld->add_rule_option("base64_decode", args);
    }
    else
    {
        data_stream.seekg(pos);
        retval = ld->add_rule_option("base64_decode");
    }

    return set_next_rule_state(data_stream) && retval;
}

/**************************
 *******  A P I ***********
 **************************/


static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new Base64Decode(cv, ld);
}

static const std::string base64_decode = "base64_decode";
static const ConvertMap base64_decode_api =
{
    base64_decode,
    ctor,
};

const ConvertMap* base64_decode_map = &base64_decode_api;

} // namespace rules
