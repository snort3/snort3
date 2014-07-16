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
// config_ignore_ports.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

namespace config
{

namespace {

class IgnorePorts : public ConversionState
{
public:
    IgnorePorts(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~IgnorePorts() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool IgnorePorts::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string keyword;
    std::string port;

    ld->open_table("binder");
    ld->open_table(); // anonymouse table

    // if the keyword is not 'tcp' or 'udp', return false;
    if (!(data_stream >> keyword) ||
        (keyword.compare("udp") && keyword.compare("tcp")) )
        return false;

    ld->open_table("when");

    while (data_stream >> port)
    {
        bool tmpval = true;
        const std::size_t colon_pos = port.find(':');
        if (colon_pos == std::string::npos)
        {
            tmpval = ld->add_list_to_table("ports", port);
        }

        else if (colon_pos == 0)
        {
            int high = std::stoi(port.substr(1));
            for (int i = 0; i <= high; i++)
            {
                bool tmpval2 = ld->add_list_to_table("ports", std::to_string(i));

                if (tmpval && !tmpval2)
                    tmpval = false;
            }
        }

        else
            {
            int low = std::stoi(port.substr(0, colon_pos));
            int high = std::stoi(port.substr(colon_pos + 1));

            for (int i = low; i <= high; i++)
            {
                bool tmpval2 = ld->add_list_to_table("ports", std::to_string(i));

                if (tmpval && !tmpval2)
                    tmpval = false;
            }
        }

        if (retval && !tmpval)
            retval = false;
    }

    ld->close_table();
    ld->open_table("use");
    ld->add_option_to_table("action", "allow");
    ld->close_table(); // table = "use"
    ld->close_table(); // table = anonymous
    ld->close_table(); // table = "binder"
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new IgnorePorts(cv, ld);
}

static const ConvertMap config_ignore_ports =
{
    "ignore_ports",
    ctor,
};

const ConvertMap* ignore_ports_map = &config_ignore_ports;

} // namespace config
