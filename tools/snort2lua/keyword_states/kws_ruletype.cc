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
// kws_ruletype.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "config_states/config_api.h"


namespace keywords
{

namespace {

class RuleType : public ConversionState
{
public:
    RuleType(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~RuleType() {};
    virtual bool convert(std::istringstream& data);
};

} // namespace


bool RuleType::convert(std::istringstream& data_stream)
{
    std::string keyword;
#if 0
    if(data_stream >> keyword)
    {

        if(keyword.back() == ':')
            keyword.pop_back();

        const ConvertMap* map = util::find_map(rules::rule_api, keyword);
        if (map)
        {
            cv->set_state(map->ctor(cv, ld));
            return true;
        }
    }
#endif
    return false;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new RuleType(cv, ld);
}

static const ConvertMap keyword_ruletype = 
{
    "ruletype",
    ctor,
};

const ConvertMap* ruletype_map = &keyword_ruletype;

} // namepsace keywords
