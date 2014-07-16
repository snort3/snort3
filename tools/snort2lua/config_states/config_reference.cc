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
// config_reference.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

namespace config
{

namespace {

class Reference : public ConversionState
{
public:
    Reference(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~Reference() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool Reference::convert(std::istringstream& data_stream)
{
    std::string keyword;

    ld->open_table("references");
    ld->open_table();

    if ((data_stream >> keyword) &&
        ld->add_option_to_table("name", keyword) &&
        (data_stream >> keyword) &&
        ld->add_option_to_table("url", keyword))
    {
        return true;
    }
    return false;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new Reference(cv, ld);
}

static const ConvertMap reference_api =
{
    "reference",
    ctor,
};

const ConvertMap* reference_map = &reference_api;

} // namespace config
