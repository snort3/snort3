//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// pps_appid.cc author davis mcpherson <davmcphe@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
namespace
{
class AppId : public ConversionState
{
public:
    AppId(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool AppId::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    table_api.open_table("appid");

    // parse the file configuration
    while (util::get_string(data_stream, keyword, ","))
    {
        bool tmpval = true;
        std::istringstream arg_stream(keyword);

        // should be guaranteed to happen.  Checking for error just cause
        if (!(arg_stream >> keyword))
            tmpval = false;
        else if (keyword == "conf")
        {
            std::string file_name;
            if( arg_stream >> file_name)
            {
                tmpval = table_api.add_unsupported_comment("conf: " + file_name);
            }
            else
            {
                data_api.failed_conversion(arg_stream, "appid: conf <missing_arg>");
                tmpval = false;
            }
        }
        else if (keyword == "memcap")
        {
            tmpval = parse_int_option("memcap", arg_stream, false);
        }
        else if (keyword == "debug")
        {
            std::string val;
            if (!(arg_stream >> val))
                data_api.failed_conversion(arg_stream,  "appid: debug <missing_arg>");
            else if (val == "yes")
                table_api.add_option("debug", true);
            else
                table_api.add_option("debug", false);
        }
        else if (keyword == "dump_ports")
        {
            table_api.add_option("dump_ports", true);
        }
        else if (keyword == "instance_id")
        {
            tmpval = parse_int_option("instance_id", arg_stream, false);
        }
        else if (keyword == "app_stats_filename")
        {
            std::string file_name;
            if (arg_stream >> file_name)
            {
                tmpval = table_api.add_option("log_stats", true);
            }
            else
            {
                data_api.failed_conversion(arg_stream,  "appid: app_stats_filename <missing_arg>");
                tmpval = false;
            }
        }
        else if (keyword == "app_stats_period")
        {
            tmpval = parse_int_option("app_stats_period", arg_stream, false);
        }
        else if (keyword == "app_stats_rollover_size")
        {
            tmpval = parse_int_option("app_stats_rollover_size", arg_stream, false);
        }
        else if (keyword == "app_stats_rollover_time")
        {
            tmpval = parse_int_option("app_stats_rollover_time", arg_stream, false);
        }
        else if (keyword == "app_detector_dir")
        {
            std::string file_name;
            if (arg_stream >> file_name)
            {
                tmpval = table_api.add_option("app_detector_dir", file_name);
            }
            else
            {
                data_api.failed_conversion(arg_stream,  "appid: app_detector_dir <missing_arg>");
                tmpval = false;
            }
        }
        else if (keyword == "thirdparty_appid_dir")
        {
            std::string file_name;
            if (arg_stream >> file_name)
            {
                tmpval = table_api.add_unsupported_comment("thirdparty_appid_dir: " + file_name);
            }
            else
            {
                data_api.failed_conversion(arg_stream,  "appid: thirdparty_appid_dir <missing_arg>");
                tmpval = false;
            }
        }
        else
        {
            tmpval = false;
        }

        if (!tmpval)
        {
            data_api.failed_conversion(arg_stream, keyword);
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
    return new AppId(c);
}

static const ConvertMap preprocessor_appid =
{
    "appid",
    ctor,
};

const ConvertMap* appid_map = &preprocessor_appid;
}

