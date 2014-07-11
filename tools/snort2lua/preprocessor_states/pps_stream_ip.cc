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
// pps_stream_ip.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "util/util.h"

namespace preprocessors
{

namespace {

class StreamIp : public ConversionState
{
public:
    StreamIp(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~StreamIp() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace


bool StreamIp::convert(std::istringstream& data_stream)
{
    std::string args;
    bool retval = true;

    ld->open_table("stream_ip");

    while (util::get_string(data_stream, args, ","))
    {
        std::string keyword;
        bool tmpval = true;
        std::istringstream arg_stream(args);


        if (!(arg_stream >> keyword))
        {
            tmpval = false;
        }
        else if (!keyword.compare("timeout"))
        {
            ld->add_diff_option_comment("timeout", "session_timeout");
            tmpval = parse_int_option("session_timeout", arg_stream);
        }
        else
        {
            tmpval = false;
        }

        if (retval && !tmpval)
            retval = false;
    }

    ld->close_table();
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new StreamIp(cv, ld);
}

static const ConvertMap preprocessor_stream_ip =
{
    "stream5_ip",
    ctor,
};

const ConvertMap* stream_ip_map = &preprocessor_stream_ip;

} // namespace preprocessors
