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
// pps_rpc_decode.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>
#include <string>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

namespace preprocessors
{

namespace {

class RpcDecode : public ConversionState
{
public:
    RpcDecode(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~RpcDecode() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool RpcDecode::convert(std::istringstream& data_stream)
{

    bool retval = true;
    std::string port_list = std::string();
    std::string keyword;

    ld->open_table("rpc_decode");
    
    while(data_stream >> keyword)
    {
        bool tmpval = true;

        if(!keyword.compare("no_alert_multiple_requests"))
            ld->add_deleted_comment("no_alert_multiple_requests");

        else if(!keyword.compare("alert_fragments"))
            ld->add_deleted_comment("alert_fragments");

        else if(!keyword.compare("no_alert_large_fragments"))
            ld->add_deleted_comment("no_alert_large_fragments");

        else if(!keyword.compare("no_alert_incomplete"))
            ld->add_deleted_comment("no_alert_incomplete");

        else if (isdigit(keyword[0]))
            port_list += ' ' + keyword;

        else
            tmpval = false;

        if (retval)
            retval = tmpval;
    }

    if (!port_list.empty())
        ld->add_comment_to_table("add port to binding --> " + port_list);

    return retval;   
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new RpcDecode(cv, ld);
}

static const ConvertMap preprocessor_rpc_decode =
{
    "rpc_decode",
    ctor,
};

const ConvertMap* rpc_decode_map = &preprocessor_rpc_decode;

} // namespace preprocessors
