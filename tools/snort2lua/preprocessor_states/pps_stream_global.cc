
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
// pps_stream_global.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "converter.h"
#include "snort2lua_util.h"

namespace {

class StreamGlobal : public ConversionState
{
public:
    StreamGlobal(Converter* cv)  : ConversionState(cv) {};
    virtual ~StreamGlobal() {};
    virtual bool convert(std::stringstream& data_stream);
};

} // namespace


bool StreamGlobal::convert(std::stringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    cv->open_table("stream");

    while(data_stream >> keyword)
    {
        bool tmpval = true;

        if(keyword.back() == ',')
            keyword.pop_back();
        
        if(keyword.empty())
            continue;



        if(!keyword.compare("flush_on_alert"))
            cv->add_deprecated_comment("flush_on_alert");

        else if(!keyword.compare("disabled"))
            cv->add_deprecated_comment("disabled");

        else if(!keyword.compare("track_tcp"))
        {
            cv->add_deprecated_comment("track_tcp");
            if(!(data_stream >> keyword)) // eat the yes/no option
                tmpval = false;
        }

        else if(!keyword.compare("track_udp"))
        {
            cv->add_deprecated_comment("track_udp");
            if(!(data_stream >> keyword)) // eat the yes/no option
                tmpval = false;
        }

        else if(!keyword.compare("track_icmp"))
        {
            cv->add_deprecated_comment("track_icmp");
            if(!(data_stream >> keyword)) // eat the yes/no option
                tmpval = false;
        }

        else if(!keyword.compare("prune_log_max"))
        {
            cv->add_deprecated_comment("prune_log_max", "histogram");
            if(!(data_stream >> keyword)) // eat the number of bytes
                tmpval = false;
        }

        else if(!keyword.compare("max_tcp"))
        {
            cv->open_table("tcp_cache");
            tmpval = parse_int_option("max_sessions", data_stream);
            cv->close_table();
        }

        else if(!keyword.compare("memcap"))
        {
            cv->open_table("tcp_cache");
            tmpval = parse_int_option("memcap", data_stream);
            cv->close_table();
        }

        else if(!keyword.compare("max_udp"))
        {
            cv->open_table("udp_cache");
            tmpval = parse_int_option("max_sessions", data_stream);
            cv->close_table();
        }

        else if(!keyword.compare("max_icmp"))
        {
            cv->open_table("icmp_cache");
            tmpval = parse_int_option("max_sessions", data_stream);
            cv->close_table();
        }

        else if(!keyword.compare("show_rebuilt_packets"))
        {
            cv->open_top_level_table("stream_tcp");
            cv->add_option_to_table("show_rebuilt_packets", true);
            cv->close_table();
        }

        else if(!keyword.compare("min_response_seconds"))
        {
            cv->open_top_level_table("active");
            tmpval = parse_int_option("min_interval", data_stream);
            cv->close_table();
        }

        else if(!keyword.compare("max_active_responses"))
        {
            cv->open_top_level_table("active");
            tmpval = parse_int_option("max_responses", data_stream);
            cv->close_table();
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
    return new StreamGlobal(cv);
}

static const ConvertMap preprocessor_stream_global = 
{
    "stream5_global",
    ctor,
};

const ConvertMap* stream_global_map = &preprocessor_stream_global;
