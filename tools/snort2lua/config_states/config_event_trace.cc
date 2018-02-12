//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// config_event_trace.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class EventTrace : public ConversionState
{
public:
    EventTrace(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool EventTrace::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string keyword;
    std::string arg;

    table_api.open_table("output");
    table_api.open_table("event_trace");

    while (util::get_string(data_stream, keyword, ", ") &&
        util::get_string(data_stream, arg, ", "))
    {
        bool tmpval = true;

        if (keyword == "file")
            table_api.add_deleted_comment("file");

        else if (keyword == "max_data")
            tmpval = table_api.add_option("max_data", std::stoi(arg));

        else
            tmpval = false;

        if (retval && !tmpval)
            retval = false;
    }

    table_api.close_table();
    table_api.close_table();
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new EventTrace(c);
}

static const ConvertMap event_trace_api =
{
    "event_trace",
    ctor,
};

const ConvertMap* event_trace_map = &event_trace_api;
} // namespace config

