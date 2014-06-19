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
// kws_config.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "converter.h"
#include "config_states/config_api.h"
#include "snort2lua_util.h"


namespace {

class Config : public ConversionState
{
public:
    Config(Converter* cv)  : ConversionState(cv) {};
    virtual ~Config() {};
    virtual bool convert(std::stringstream& data);
};

} // namespace


bool Config::convert(std::stringstream& data_stream)
{
    std::string keyword;

    if(data_stream >> keyword)
    {

        if(keyword.back() == ':')
            keyword.pop_back();

        const ConvertMap* map = util::find_map(config_api, keyword);
        if (map)
        {
            converter->set_state(map->ctor(converter));
            return true;
        }
    }

    return false;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv)
{
    return new Config(cv);
}

static const ConvertMap keyword_config = 
{
    "config",
    ctor,
};

const ConvertMap* config_map = &keyword_config;
