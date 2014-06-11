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
// config.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>
#include <iomanip>

#include "conversion_state.h"
#include "converter.h"
#include "snort2lua_util.h"


namespace {

class Include : public ConversionState
{
public:
    Include(Converter* cv)  : ConversionState(cv) {};
    virtual ~Include() {};
    virtual bool convert(std::stringstream& data, std::ofstream&);
};

} // namespace


bool Include::convert(std::stringstream& data_stream, std::ofstream&)
{
#if 0
    std::string keyword;

    if(data >> keyword)
    {
        const ConvertMap* map = util::find_map(output_api, keyword);
        if (map)
        {
            converter->set_state(map->ctor(converter));
            return true;
        }
    }

    return false;    
#endif

    data_stream.setstate(std::basic_ios<char>::eofbit);
    return true;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv)
{
    return new Include(cv);
}

static const ConvertMap keyword_include = 
{
    "include",
    ctor,
};

const ConvertMap* include_map = &keyword_include;
