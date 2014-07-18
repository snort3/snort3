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
// config_event_trace.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

namespace config
{

namespace {

class EventTrace : public ConversionState
{
public:
    EventTrace(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~EventTrace() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool EventTrace::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string keyword;
    std::string arg;

    ld->open_table("output");
    ld->open_table("event_trace");

    while (util::get_string(data_stream, keyword, ", ") &&
            util::get_string(data_stream, arg, ", "))
    {
        bool tmpval = true;

        if (!keyword.compare("file"))
            tmpval = ld->add_option_to_table("file", arg);

        else if (!keyword.compare("max_data"))
            tmpval = ld->add_option_to_table("max_data", std::stoi(arg));

        else
            tmpval = false;


        if (retval && !tmpval)
            retval = false;
    }

    ld->close_table();
    ld->close_table();
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new EventTrace(cv, ld);
}

static const ConvertMap event_trace_api =
{
    "event_trace",
    ctor,
};

const ConvertMap* event_trace_map = &event_trace_api;

} // namespace config
