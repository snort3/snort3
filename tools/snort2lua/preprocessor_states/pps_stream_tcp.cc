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
// config.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "util/util.h"

namespace preprocessors
{

namespace {

class StreamTcp : public ConversionState
{
public:
    StreamTcp(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~StreamTcp() {};
    virtual bool convert(std::istringstream& data_stream);

private:
    bool parse_small_segments(std::istringstream& data_stream);
    bool parse_ports(std::istringstream& data_stream);
    bool parse_protocol(std::istringstream& data_stream);
};

} // namespace

bool StreamTcp::parse_small_segments(std::istringstream& stream)
{
    int consec_segs;
    std::string bytes;
    int min_bytes;
    std::string ignore_ports;

    if (!(stream >> consec_segs) ||
        !(stream >> bytes) ||
        bytes.compare("bytes") ||
        !(stream >> min_bytes))
        return false;



    ld->open_table("small_segments");
    ld->add_option_to_table("count", consec_segs);
    ld->add_option_to_table("maximum_size", min_bytes);
    ld->close_table();


    if (!(stream >> ignore_ports))
        return true;

    // otherwise the next argument MUST be ignore_ports
    if (ignore_ports.compare("ignore_ports"))
        return false;


    ld->open_table("small_segments");
    long long port;

    // extracting into an int since thats what they should be!
    while(stream >> port)
        ld->add_list_to_table("ignore_ports", std::to_string(port));

    ld->close_table();

    if (!stream.eof())
        return false;
    return true;
}


bool StreamTcp::parse_ports(std::istringstream& stream)
{
    std::string s_val;
    std::string dir;
    std::string opt_name;
    bool retval = true;

    if(!(stream >> dir))
        return false;

    if( !dir.compare("client"))
        opt_name = "client_ports";

    else if( !dir.compare("server"))
        opt_name = "server_ports";

    else if( !dir.compare("both"))

        opt_name = "both_ports";

    else
        return false;


    while(stream >> s_val)
        retval = ld->add_list_to_table(opt_name, s_val) && retval;


    ld->add_diff_option_comment("port " + dir, opt_name);
    ld->add_list_to_table(opt_name, s_val);
    return retval;
}

bool StreamTcp::parse_protocol(std::istringstream& stream)
{
    std::string dir;
    std::string lua_dir;
    std::string protocol;
    bool tmpval = true;

    // this may seem idiotic, but Snort does not actually require
    // any keywords for the 'protocol' keyword.  So, this is
    // still technically correct.
    if (!(stream >> dir))
        return true;


    if (!dir.compare("client"))
        lua_dir = "client_protocols";

    else if (!dir.compare("server"))
        lua_dir = "server_protocols";

    else if (!dir.compare("both"))
        lua_dir = "both_protocols";

    else
        return false;

    // TODO: update funcitnoality if Snort++ StreamTcpModule is updated

    while (stream >> protocol)
        tmpval = ld->add_list_to_table(lua_dir, protocol) && tmpval;

    ld->add_diff_option_comment("protocol " + dir, lua_dir);
    return true;
}

bool StreamTcp::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    ld->open_table("stream_tcp");


    while(util::get_string(data_stream, keyword, ","))
    {
        bool tmpval = true;
        std::istringstream arg_stream(keyword);

        // should be gauranteed to happen.  Checking for error just cause
        if (!(arg_stream >> keyword))
            tmpval = false;



        if (!keyword.compare("policy"))
            tmpval = parse_string_option("policy", arg_stream);

        else if (!keyword.compare("overlap_limit"))
            tmpval = parse_int_option("overlap_limit", arg_stream);

        else if (!keyword.compare("max_window"))
            tmpval = parse_int_option("max_window", arg_stream);

        else if (!keyword.compare("require_3whs"))
            tmpval = parse_int_option("require_3whs", arg_stream, false);

        else if (!keyword.compare("small_segments"))
            tmpval = parse_small_segments(arg_stream);

        else if (!keyword.compare("ignore_any_rules"))
            tmpval = ld->add_option_to_table("ignore_any_rules", true);

        else if (!keyword.compare("ports"))
            tmpval = parse_ports(arg_stream);

        else if (!keyword.compare("detect_anomalies"))
            ld->add_deprecated_comment("detect_anomalies");

        else if (!keyword.compare("dont_store_large_packets"))
            ld->add_deprecated_comment("dont_store_large_packets");

        else if (!keyword.compare("check_session_hijacking"))
            ld->add_deprecated_comment("check_session_hijacking");

        else if (!keyword.compare("flush_factor"))
            tmpval = parse_int_option("flush_factor", arg_stream);

        else if(!keyword.compare("protocol"))
            tmpval = parse_protocol(arg_stream);

        else if (!keyword.compare("bind_to"))
        {
            ld->add_diff_option_comment("bind_to", "bindings");
            if (!eat_option(arg_stream))
                tmpval = false;
        }

        else if (!keyword.compare("dont_reassemble_async"))
        {
            ld->add_diff_option_comment("dont_reassemble_async", "reassemble_async");
            tmpval = ld->add_option_to_table("reassemble_async", false);
        }

        else if (!keyword.compare("use_static_footprint_sizes"))
        {
            ld->add_diff_option_comment("footprint", "use_static_footprint_sizes");
            tmpval = ld->add_option_to_table("footprint", true);
        }

        else if (!keyword.compare("timeout"))
        {
            ld->add_diff_option_comment("timeout", "session_timeout");
            tmpval = parse_int_option("session_timeout", arg_stream);
        }

        else if (!keyword.compare("max_queued_segs"))
        {
            ld->add_diff_option_comment("max_queued_segs", "queue_limit.max_segments");
            ld->open_table("queue_limit");
            tmpval = parse_int_option("max_segments", arg_stream);
            ld->close_table();
        }

        else if (!keyword.compare("max_queued_bytes"))
        {
            ld->add_diff_option_comment("max_queued_bytes", "queue_limit.max_bytes");
            ld->open_table("queue_limit");
            tmpval = parse_int_option("max_bytes", arg_stream);
            ld->close_table();
        }

        else
        {
            tmpval = false;
        }

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
    return new StreamTcp(cv, ld);
}

static const ConvertMap preprocessor_stream_tcp = 
{
    "stream5_tcp",
    ctor,
};

const ConvertMap* stream_tcp_map = &preprocessor_stream_tcp;

} // namespace preprocessors
