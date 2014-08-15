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
// config_decode_esp.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/s2l_util.h"

namespace config
{

namespace {


class DecodeEsp : public ConversionState
{
public:
    DecodeEsp(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~DecodeEsp() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace


bool DecodeEsp::convert(std::istringstream& data_stream)
{
    std::string type;
    bool retval = true;

    if (!(data_stream >> type))
        return false;


    ld->open_table("esp");

    if (!type.compare("1") ||
        !type.compare("on") ||
        !type.compare("yes") ||
        !type.compare("true") ||
        !type.compare("enable"))
    {
        ld->add_diff_option_comment("config decode_esp: " + type, "decode_esp = true");
        retval = ld->add_option_to_table("decode_esp", true);
    }
    else if (!type.compare("0") ||
        !type.compare("no") ||
        !type.compare("off") ||
        !type.compare("false") ||
        !type.compare("disable"))
    {
        ld->add_diff_option_comment("config decode_esp: " + type, "decode_esp = false");
        retval = ld->add_option_to_table("decode_esp", false);
    }
    else
        return false;

    // stop parsing, even if additional options available
    data_stream.setstate(std::ios::eofbit);
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/


static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new DecodeEsp(cv, ld);
}

static const ConvertMap decode_esp_api =
{
    "decode_esp",
    ctor,
};

const ConvertMap* decode_esp_map = &decode_esp_api;

} // namespace config
