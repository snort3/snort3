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
// kws_suppress.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "converter.h"
#include "snort2lua_util.h"
//#include "suppress_states/suppress_api.h"

namespace {

class Suppress : public ConversionState
{
public:
    Suppress(Converter* cv)  : ConversionState(cv) {};
    virtual ~Suppress() {};
    virtual bool convert(std::stringstream& data);
};

} // namespace


bool Suppress::convert(std::stringstream& data_stream)
{
    bool retval = true;
    std::string keyword;

    cv->open_table("suppress");
    cv->add_diff_option_comment("gen_id", "gid");
    cv->add_diff_option_comment("sig_id", "sid");
    cv->open_table();

    while(data_stream >> keyword)
    {
        bool tmpval = true;

        if(keyword.back() == ',')
            keyword.pop_back();

        if(keyword.empty())
            continue;

        if (!keyword.compare("track"))
            tmpval = parse_string_option("track", data_stream);

        else if (!keyword.compare("ip"))
            tmpval = parse_string_option("ip", data_stream);

        else if(!keyword.compare("gen_id"))
            tmpval = parse_int_option("gid", data_stream);

        else if (!keyword.compare("sig_id"))
            tmpval = parse_int_option("sid", data_stream);

        else
            tmpval = false;

        if (retval)
            retval = tmpval;
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv)
{
    return new Suppress(cv);
}

static const ConvertMap keyword_supress =
{
    "suppress",
    ctor,
};

const ConvertMap* supress_map = &keyword_supress;
