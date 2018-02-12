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
// config_event_queue.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class EventQueue : public ConversionState
{
public:
    EventQueue(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool EventQueue::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    table_api.open_table("event_queue");

    while (util::get_string(data_stream, keyword, ", "))
    {
        bool tmpval = true;

        if (keyword == "process_all_events")
            tmpval = table_api.add_option("process_all_events", true);

        else if (keyword == "max_queue")
        {
            std::string val;

            if (util::get_string(data_stream, val, ", "))
                tmpval = table_api.add_option("max_queue", std::stoi(val));
            else
                tmpval = false;
        }
        else if (keyword == "log")
        {
            std::string val;

            if (util::get_string(data_stream, val, ", "))
                tmpval = table_api.add_option("log", std::stoi(val));
            else
                tmpval = false;
        }
        else if (keyword == "order_events")
        {
            std::string val;
            if (util::get_string(data_stream, val, ", "))
                tmpval = table_api.add_option("order_events", val);
            else
                tmpval = false;
        }
        else
            tmpval = false;

        if (retval && !tmpval)
            retval = false;
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new EventQueue(c);
}

static const ConvertMap event_queue_api =
{
    "event_queue",
    ctor,
};

const ConvertMap* event_queue_map = &event_queue_api;
} // namespace config

