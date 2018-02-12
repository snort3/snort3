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
// config_decode_esp.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class DecodeEsp : public ConversionState
{
public:
    DecodeEsp(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool DecodeEsp::convert(std::istringstream& data_stream)
{
    std::string type;
    bool retval = true;

    if (!(data_stream >> type))
        return false;

    table_api.open_table("esp");

    if (type == "1" ||
        type == "on" ||
        type == "yes" ||
        type == "true" ||
        type == "enable")
    {
        table_api.add_diff_option_comment("config decode_esp: " + type, "decode_esp = true");
        retval = table_api.add_option("decode_esp", true);
    }
    else if (type == "0" ||
        type == "no" ||
        type == "off" ||
        type == "false" ||
        type == "disable")
    {
        table_api.add_diff_option_comment("config decode_esp: " + type, "decode_esp = false");
        retval = table_api.add_option("decode_esp", false);
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

static ConversionState* ctor(Converter& c)
{
    return new DecodeEsp(c);
}

static const ConvertMap decode_esp_api =
{
    "decode_esp",
    ctor,
};

const ConvertMap* decode_esp_map = &decode_esp_api;
} // namespace config

