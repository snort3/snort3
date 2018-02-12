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
// pps_frag3_engine.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace
{
class Frag3Engine : public ConversionState
{
public:
    explicit Frag3Engine(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;

private:
    std::string choose_table_name(std::istringstream& data_stream);
};
} // namespace

std::string Frag3Engine::choose_table_name(std::istringstream& data_stream)
{
    static uint32_t binding_id = 0;
    const std::istringstream::off_type pos = data_stream.tellg();
    std::string keyword;

    while (data_stream >> keyword)
    {
        if (keyword == "bind_to")
        {
            data_stream.clear();
            data_stream.seekg(pos);
            return "stream_ip_" + std::to_string(binding_id++);
        }
    }

    data_stream.clear();
    data_stream.seekg(pos);
    return "stream_ip";
}

bool Frag3Engine::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string keyword;

    const std::string table_name = choose_table_name(data_stream);
    table_api.open_table(table_name);

    while (data_stream >> keyword)
    {
        if (keyword.back() == ',')
            keyword.pop_back();

        if (keyword.empty())
            continue;

        if (keyword == "detect_anomalies")
            table_api.add_deleted_comment("detect_anomalies");

        else if (keyword == "bind_to")
        {
            std::string ip_list;

            if ( !(data_stream >> ip_list) )
            {
                data_api.failed_conversion(data_stream, "bind_to <ip_list>");
            }
            else
            {
                auto& b = cv.make_binder();
                b.set_when_proto("ip");
                b.add_when_net(ip_list);
                b.set_use_type("stream_ip");
                b.set_use_name(table_name);
            }
        }
        else if (keyword == "min_ttl")
        {
            if (!parse_int_option("min_ttl", data_stream, false))
            {
                data_api.failed_conversion(data_stream, "min_ttl <integer>");
                retval = false;
            }
        }
        else if (keyword == "overlap_limit")
        {
            if (!parse_int_option("max_overlaps", data_stream, false))
            {
                data_api.failed_conversion(data_stream, "max_overlaps <integer>");
                retval = false;
            }

            table_api.add_diff_option_comment("overlap_limit", "max_overlaps");
        }
        else if (keyword == "min_fragment_length")
        {
            if (!parse_int_option("min_frag_length", data_stream, false))
            {
                data_api.failed_conversion(data_stream, "min_frag_length <integer>");
                retval = false;
            }
            table_api.add_diff_option_comment("min_fragment_length", "min_frag_length");
        }
        else if (keyword == "timeout")
        {
            std::string val;
            table_api.add_diff_option_comment("timeout", "session_timeout");

            if (data_stream >> val)
            {
                int seconds = std::stoi(val);
                if (seconds == 0)
                {
                    table_api.add_option("session_timeout", 256);
                    table_api.add_diff_option_comment("preprocessor frag3_engine: timeout 0",
                        "session_timeout 256");
                }
                else
                {
                    table_api.add_option("session_timeout", seconds);
                }
            }
        }
        else if (keyword == "policy")
        {
            std::string policy;

            if (!(data_stream >> policy))
            {
                data_api.failed_conversion(data_stream, "policy <missing_policy>");
                retval = false;
            }
            else if (policy == "first")
                table_api.add_option("policy", "first");

            else if (policy == "bsd")
                table_api.add_option("policy", "bsd");

            else if (policy == "last")
                table_api.add_option("policy", "last");

            else if (policy == "windows")
                table_api.add_option("policy", "windows");

            else if (policy == "linux")
                table_api.add_option("policy", "linux");

            else if (policy == "solaris")
                table_api.add_option("policy", "solaris");

            else if (policy == "bsd-right")
            {
                table_api.add_diff_option_comment("policy bsd-right", "policy = bsd_right");
                table_api.add_option("policy", "bsd_right");
            }
            else
            {
                data_api.failed_conversion(data_stream, "policy '" + keyword + "'");
                retval = false;
            }
        }
        else
        {
            data_api.failed_conversion(data_stream, keyword);
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
    return new Frag3Engine(c);
}

static const ConvertMap preprocessor_frag3_engine =
{
    "frag3_engine",
    ctor,
};

const ConvertMap* frag3_engine_map = &preprocessor_frag3_engine;
} // namespace preprocessors

