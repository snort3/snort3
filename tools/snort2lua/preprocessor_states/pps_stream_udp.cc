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
// pps_stream_udp.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "converter.h"
#include "snort2lua_util.h"

namespace {

class StreamUdp : public ConversionState
{
public:
    StreamUdp(Converter* cv)  : ConversionState(cv) {};
    virtual ~StreamUdp() {};
    virtual bool convert(std::stringstream& data_stream);
};

} // namespace

bool StreamUdp::convert(std::stringstream& data_stream)
{

    bool retval = true;
    std::string keyword;

    cv->open_table("stream_udp");

    while(data_stream >> keyword)
    {
        bool tmpval = true;

        if(keyword.back() == ',')
            keyword.pop_back();
        
        if(keyword.empty())
            continue;
        
        if(!keyword.compare("ignore_any_rules"))
            tmpval = cv->add_option_to_table("ignore_any_rules", true);

        else if(!keyword.compare("timeout"))
        {
            cv->add_deprecated_comment("timeout", "session_timeout");
            tmpval = parse_int_option("session_timeout", data_stream);
        }

        else
            tmpval = false;

        if (retval)
            retval = tmpval;
    }

    return retval;    
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv)
{
    return new StreamUdp(cv);
}

static const ConvertMap preprocessor_stream_udp = 
{
    "stream5_udp",
    ctor,
};

const ConvertMap* stream_udp_map = &preprocessor_stream_udp;
