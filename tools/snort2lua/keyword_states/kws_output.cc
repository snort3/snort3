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
// kws_output.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "util/util.h"
#include "output_states/output_api.h"



namespace {

class Output : public ConversionState
{
public:
    Output(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~Output() {};
    virtual bool convert(std::stringstream& data);
};

} // namespace


bool Output::convert(std::stringstream& data_stream)
{
    std::string keyword;

    if(data_stream >> keyword)
    {
        const ConvertMap* map = util::find_map(output_api, keyword);
        if (map)
        {
            cv->set_state(map->ctor(cv, ld));
            return true;
        }
    }

    return false;    
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new Output(cv, ld);
}

static const ConvertMap keyword_output = 
{
    "output",
    ctor,
};

const ConvertMap* output_map = &keyword_output;
