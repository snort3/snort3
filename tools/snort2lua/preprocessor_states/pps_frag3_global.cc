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
// pps_frag3_global.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

namespace preprocessors
{

namespace {

class Frag3Global : public ConversionState
{
public:
    Frag3Global(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~Frag3Global() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool Frag3Global::convert(std::istringstream& data_stream)
{

    bool retval = true;
    std::string keyword;

    ld->open_table("stream_ip");


    // full options are comma seperated
    while(util::get_string(data_stream, keyword, ","))
    {
        bool tmpval = true;

        // suboptions are space seperated
        std::istringstream args_stream(keyword);
        args_stream >> keyword;
        
        if(!keyword.compare("disabled"))
            ld->add_deleted_comment("disabled");

        else if(!keyword.compare("max_frags"))
            tmpval = parse_int_option("max_frags", args_stream);
        
        else if(!keyword.compare("memcap"))
            tmpval = parse_deleted_option("memcap", args_stream);

        else if(!keyword.compare("prealloc_memcap"))
            tmpval = parse_deleted_option("prealloc_memcap", args_stream);

        else if(!keyword.compare("prealloc_frags"))
            tmpval = parse_deleted_option("prealloc_frags", args_stream);

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

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new Frag3Global(cv, ld);
}

static const ConvertMap preprocessor_frag3_global =
{
    "frag3_global",
    ctor,
};

const ConvertMap* frag3_global_map = &preprocessor_frag3_global;

} // namespace preprocessors
