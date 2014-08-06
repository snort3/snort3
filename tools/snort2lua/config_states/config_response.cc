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
// config_response.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/s2l_util.h"

namespace config
{

namespace {

class Response : public ConversionState
{
public:
    Response(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~Response() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool Response::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    ld->open_table("active");

    while (util::get_string(data_stream, keyword, ", "))
    {
        bool tmpval = true;
        std::string val;

        if (!util::get_string(data_stream, val, ", "))
            tmpval = false;

        else if (!keyword.compare("attempts"))
            tmpval = ld->add_option_to_table("attempts", std::stoi(val));

        else if (!keyword.compare("device"))
            tmpval = ld->add_option_to_table("device", val);

        else if (!keyword.compare("dst_mac"))
            tmpval = ld->add_option_to_table("dst_mac", val);

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

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new Response(cv, ld);
}

static const ConvertMap response_api =
{
    "response",
    ctor,
};

const ConvertMap* response_map = &response_api;

} // namespace config