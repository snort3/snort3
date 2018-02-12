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
// config_response.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class Response : public ConversionState
{
public:
    Response(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool Response::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    table_api.open_table("active");

    while (util::get_string(data_stream, keyword, ", "))
    {
        bool tmpval = true;
        std::string val;

        if (!util::get_string(data_stream, val, ", "))
            tmpval = false;

        else if (keyword == "attempts")
            tmpval = table_api.add_option("attempts", std::stoi(val));

        else if (keyword == "device")
            tmpval = table_api.add_option("device", val);

        else if (keyword == "dst_mac")
            tmpval = table_api.add_option("dst_mac", val);

        else
            tmpval = false;

        if (retval && !tmpval)
            retval = false;
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new Response(c); }

static const ConvertMap response_api =
{
    "response",
    ctor,
};

const ConvertMap* response_map = &response_api;
} // namespace config

