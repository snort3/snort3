
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
// pps_stream_global.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

namespace preprocessors
{

namespace {

class StreamGlobal : public ConversionState
{
public:
    StreamGlobal(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~StreamGlobal() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace


bool StreamGlobal::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    ld->open_table("stream");

    while(util::get_string(data_stream, keyword, ","))
    {
        bool tmpval = true;
        std::istringstream arg_stream(keyword);

        // should be gauranteed to happen.  Checking for error just cause
        if (!(arg_stream >> keyword))
            tmpval = false;

        else if (!keyword.compare("flush_on_alert"))
            ld->add_deleted_comment("flush_on_alert");

        else if (!keyword.compare("disabled"))
            ld->add_deleted_comment("disabled");

        else if (!keyword.compare("enable_ha"))
            ld->add_unsupported_comment("enable_ha");

        else if (!keyword.compare("no_midstream_drop_alerts"))
            ld->add_deleted_comment("no_midstream_drop_alerts");

        else if (!keyword.compare("track_tcp"))
            tmpval = parse_deleted_option("track_tcp", arg_stream);

        else if (!keyword.compare("track_udp"))
            tmpval = parse_deleted_option("track_udp", arg_stream);

        else if (!keyword.compare("track_icmp"))
            tmpval = parse_deleted_option("track_icmp", arg_stream);

        else if (!keyword.compare("track_ip"))
            tmpval = parse_deleted_option("track_ip", arg_stream);

        else if (!keyword.compare("prune_log_max"))
        {
            ld->add_diff_option_comment("prune_log_max", "histogram");
            if (!eat_option(arg_stream))
                tmpval = false;
        }

        else if (!keyword.compare("max_tcp"))
        {
            ld->open_table("tcp_cache");
            ld->add_diff_option_comment("max_tcp", "max_sessions");
            tmpval = parse_int_option("max_sessions", arg_stream);
            ld->close_table();
        }

        else if (!keyword.compare("max_tcp"))
        {
            ld->open_table("tcp_cache");
            tmpval = parse_int_option("max_sessions", arg_stream);
            ld->close_table();
        }

        else if (!keyword.compare("tcp_cache_nominal_timeout"))
        {
            ld->open_table("tcp_cache");
            ld->add_diff_option_comment("tcp_cache_nominal_timeout", "pruning_timeout");
            tmpval = parse_int_option("pruning_timeout", arg_stream);
            ld->close_table();
        }

        else if (!keyword.compare("tcp_cache_pruning_timeout"))
        {
            ld->open_table("tcp_cache");
            ld->add_diff_option_comment("tcp_cache_pruning_timeout", "idle_timeout");
            tmpval = parse_int_option("idle_timeout", arg_stream);
            ld->close_table();
        }

        else if (!keyword.compare("memcap"))
        {
            ld->open_table("tcp_cache");
            tmpval = parse_int_option("memcap", arg_stream);
            ld->close_table();
        }

        else if (!keyword.compare("max_udp"))
        {
            ld->open_table("udp_cache");
            ld->add_diff_option_comment("max_udp","max_sessions");
            tmpval = parse_int_option("max_sessions", arg_stream);
            ld->close_table();
        }

        else if (!keyword.compare("udp_cache_pruning_timeout"))
        {
            ld->open_table("udp_cache");
            ld->add_diff_option_comment("udp_cache_pruning_timeout","pruning_timeout");
            tmpval = parse_int_option("pruning_timeout", arg_stream);
            ld->close_table();
        }

        else if (!keyword.compare("udp_cache_nominal_timeout"))
        {
            ld->open_table("udp_cache");
            ld->add_diff_option_comment("udp_cache_nominal_timeout","idle_timeout");
            tmpval = parse_int_option("idle_timeout", arg_stream);
            ld->close_table();
        }

        else if (!keyword.compare("max_icmp"))
        {
            ld->open_table("icmp_cache");
            ld->add_diff_option_comment("max_icmp","max_sessions");
            tmpval = parse_int_option("max_sessions", arg_stream);
            ld->close_table();
        }

        else if (!keyword.compare("max_ip"))
        {
            ld->open_table("ip_cache");
            ld->add_diff_option_comment("max_ip","max_sessions");
            tmpval = parse_int_option("max_sessions", arg_stream);
            ld->close_table();
        }

        else if (!keyword.compare("show_rebuilt_packets"))
        {
            ld->open_top_level_table("stream_tcp");
            ld->add_option_to_table("show_rebuilt_packets", true);
            ld->close_table();
        }

        else if (!keyword.compare("min_response_seconds"))
        {
            ld->open_top_level_table("active");
            ld->add_diff_option_comment("min_response_seconds","min_interval");
            tmpval = parse_int_option("min_interval", arg_stream);
            ld->close_table();
        }

        else if (!keyword.compare("max_active_responses"))
        {
            ld->open_top_level_table("active");
            ld->add_diff_option_comment("max_active_responses","max_responses");
            tmpval = parse_int_option("max_responses", arg_stream);
            ld->close_table();
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

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new StreamGlobal(cv, ld);
}

static const ConvertMap preprocessor_stream_global = 
{
    "stream5_global",
    ctor,
};

const ConvertMap* stream_global_map = &preprocessor_stream_global;

} // namespace preprocessors
