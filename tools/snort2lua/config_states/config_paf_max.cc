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
// config_paf_max.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

namespace config
{

namespace {

class PafMax : public ConversionState
{
public:
    PafMax(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~PafMax() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool PafMax::convert(std::istringstream& data_stream)
{
    bool retval = true;
    int val;

    ld->open_table("stream_tcp");

    if (data_stream >> val)
    {
        if (val < 1460)
            retval = ld->add_diff_option_comment("paf_max [0:63780]", "paf_max [1460:63780]");
        else
            retval = ld->add_option_to_table("paf_max", val);
    }
    else
        retval = false;

    ld->close_table();
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new PafMax(cv, ld);
}

static const ConvertMap paf_max_api =
{
    "paf_max",
    ctor,
};

const ConvertMap* paf_max_map = &paf_max_api;

} // namespace config
