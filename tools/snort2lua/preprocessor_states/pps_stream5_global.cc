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
// pps_stream_global.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
namespace
{
class StreamGlobal : public ConversionState
{
public:
    StreamGlobal(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool StreamGlobal::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    table_api.open_table("stream");

    while (util::get_string(data_stream, keyword, ","))
    {
        bool tmpval = true;
        std::istringstream arg_stream(keyword);

        // should be guaranteed to happen.  Checking for error just cause
        if (!(arg_stream >> keyword))
            tmpval = false;

        else if (keyword == "flush_on_alert")
            table_api.add_deleted_comment("flush_on_alert");

        else if (keyword == "disabled")
            table_api.add_deleted_comment("disabled");

        else if (keyword == "enable_ha")
            table_api.add_unsupported_comment("enable_ha");

        else if (keyword == "memcap")
            table_api.add_deleted_comment("memcap");

        else if (keyword == "no_midstream_drop_alerts")
            table_api.add_deleted_comment("no_midstream_drop_alerts");

        else if (keyword == "track_tcp")
            tmpval = parse_deleted_option("track_tcp", arg_stream);

        else if (keyword == "track_udp")
            tmpval = parse_deleted_option("track_udp", arg_stream);

        else if (keyword == "track_icmp")
            tmpval = parse_deleted_option("track_icmp", arg_stream);

        else if (keyword == "track_ip")
            tmpval = parse_deleted_option("track_ip", arg_stream);

        else if (keyword == "prune_log_max")
        {
            table_api.add_diff_option_comment("prune_log_max", "histogram");
            if (!eat_option(arg_stream))
                tmpval = false;
        }
        else if (keyword == "max_tcp")
        {
            table_api.open_table("tcp_cache");
            table_api.add_diff_option_comment("max_tcp", "max_sessions");
            tmpval = parse_int_option("max_sessions", arg_stream, false);
            table_api.close_table();
        }
        else if (keyword == "tcp_cache_nominal_timeout")
        {
            table_api.open_table("tcp_cache");
            table_api.add_diff_option_comment("tcp_cache_nominal_timeout", "pruning_timeout");
            tmpval = parse_int_option("pruning_timeout", arg_stream, false);
            table_api.close_table();
        }
        else if (keyword == "tcp_cache_pruning_timeout")
        {
            table_api.open_table("tcp_cache");
            table_api.add_diff_option_comment("tcp_cache_pruning_timeout", "idle_timeout");
            tmpval = parse_int_option("idle_timeout", arg_stream, false);
            table_api.close_table();
        }
        else if (keyword == "max_udp")
        {
            table_api.open_table("udp_cache");
            table_api.add_diff_option_comment("max_udp","max_sessions");
            tmpval = parse_int_option("max_sessions", arg_stream, false);
            table_api.close_table();
        }
        else if (keyword == "udp_cache_pruning_timeout")
        {
            table_api.open_table("udp_cache");
            table_api.add_diff_option_comment("udp_cache_pruning_timeout","pruning_timeout");
            tmpval = parse_int_option("pruning_timeout", arg_stream, false);
            table_api.close_table();
        }
        else if (keyword == "udp_cache_nominal_timeout")
        {
            table_api.open_table("udp_cache");
            table_api.add_diff_option_comment("udp_cache_nominal_timeout","idle_timeout");
            tmpval = parse_int_option("idle_timeout", arg_stream, false);
            table_api.close_table();
        }
        else if (keyword == "max_icmp")
        {
            table_api.open_table("icmp_cache");
            table_api.add_diff_option_comment("max_icmp","max_sessions");
            tmpval = parse_int_option("max_sessions", arg_stream, false);
            table_api.close_table();
        }
        else if (keyword == "max_ip")
        {
            table_api.open_table("ip_cache");
            table_api.add_diff_option_comment("max_ip","max_sessions");
            tmpval = parse_int_option("max_sessions", arg_stream, false);
            table_api.close_table();
        }
        else if (keyword == "show_rebuilt_packets")
        {
            table_api.open_top_level_table("stream_tcp");
            table_api.add_option("show_rebuilt_packets", true);
            table_api.close_table();
        }
        else if (keyword == "min_response_seconds")
        {
            table_api.open_top_level_table("active");
            table_api.add_diff_option_comment("min_response_seconds","min_interval");
            tmpval = parse_int_option("min_interval", arg_stream, false);
            table_api.close_table();
        }
        else if (keyword == "max_active_responses")
        {
            table_api.open_top_level_table("active");
            table_api.add_diff_option_comment("max_active_responses","max_responses");
            tmpval = parse_int_option("max_responses", arg_stream, false);
            table_api.close_table();
            table_api.open_top_level_table("reject");
            table_api.add_option("reset", "both");
            table_api.close_table();
        }
        else
        {
            tmpval = false;
        }

        if (!tmpval)
        {
            data_api.failed_conversion(data_stream, arg_stream.str());
            retval = false;
        }
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new StreamGlobal(c);
}

static const ConvertMap preprocessor_stream_global =
{
    "stream5_global",
    ctor,
};

const ConvertMap* stream_global_map = &preprocessor_stream_global;
} // namespace preprocessors

