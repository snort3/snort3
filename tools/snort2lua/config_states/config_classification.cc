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
// config_classification.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

namespace config
{

namespace {

class Classification : public ConversionState
{
 public:
    Classification(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {}
    virtual ~Classification() {}
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool Classification::convert(std::istringstream& data_stream)
{
    std::string keyword;
    int priority;

    ld->open_table("classifications");
    ld->open_table();
    std::getline(data_stream, keyword, ',');

    if (data_stream.bad())
        return false;

    util::trim(keyword);
    ld->add_option_to_table("name", keyword);
    keyword.clear();
    std::getline(data_stream, keyword, ',');

    if (data_stream.bad())
        return false;

    util::trim(keyword);
    ld->add_option_to_table("text", keyword);

    if(!(data_stream >> priority))
        return false;

    ld->add_option_to_table("priority", priority);
    return true;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new Classification(cv, ld);
}

static const ConvertMap classification_api =
{
    "classification",
    ctor,
};

const ConvertMap* classification_map = &classification_api;

} // namespace config