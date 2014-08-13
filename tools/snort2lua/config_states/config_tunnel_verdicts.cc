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
// config_tunnel_verdicts.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/s2l_util.h"

namespace config
{

namespace {

class TunnelVerdicts : public ConversionState
{
public:
    TunnelVerdicts(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~TunnelVerdicts() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool TunnelVerdicts::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string val;

    ld->open_table("alerts");

    while (util::get_string(data_stream, val, ", "))
    {
        bool tmpval = ld->add_list_to_table("tunnel_verdicts", val);

        if (retval && !tmpval)
            retval = false;
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new TunnelVerdicts(cv, ld);
}

static const ConvertMap tunnel_verdicts_api =
{
    "tunnel_verdicts",
    ctor,
};

const ConvertMap* tunnel_verdicts_map = &tunnel_verdicts_api;

} // namespace config
