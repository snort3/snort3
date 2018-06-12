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
// pps_reputation.cc author Bhagya Tholpady <bbantwal@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
namespace
{
class Reputation : public ConversionState
{
public:
    Reputation(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool Reputation::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    table_api.open_table("reputation");

    // parse the file configuration
    while (util::get_string(data_stream, keyword, ","))
    {
        bool tmpval = true;
        std::istringstream arg_stream(keyword);

        // should be guaranteed to happen.  Checking for error just cause
        if (!(arg_stream >> keyword))
            tmpval = false;

        else if (keyword == "shared_mem")
        {
            table_api.add_diff_option_comment("shared_mem", "list_dir");

            std::string path;
            if( arg_stream >> path)
            {
                tmpval = table_api.add_option("list_dir", path);
            }
            else
            {
                data_api.failed_conversion(arg_stream, "reputation: shared_mem <missing_arg>");
                tmpval = false;
            }
        }

        else if (keyword == "shared_refresh")
            table_api.add_deleted_comment("shared_refresh");

        else if (keyword == "blacklist")
        {
            std::string file_name;
            if( arg_stream >> file_name)
            {
                tmpval = table_api.add_option("blacklist", file_name);
            }
            else
            {
                data_api.failed_conversion(arg_stream, "reputation: blacklist <missing_arg>");
                tmpval = false;
            }
        }
        else if (keyword == "memcap")
        {
            tmpval = parse_int_option("memcap", arg_stream, false);
        }
        else if (keyword == "nested_ip")
        {
            std::string val;
            if (!(arg_stream >> val))
                data_api.failed_conversion(arg_stream,  "reputation: nested_ip <missing_arg>");
            else if (val == "inner")
                table_api.add_option("nested_ip", "inner");
            else if (val == "outer")
                table_api.add_option("nested_ip", "outer");
            else if (val == "both")
                table_api.add_option("nested_ip", "all");
            else
            {
                data_api.failed_conversion(arg_stream, "reputation: nested_ip " + val);
            }
        }
        else if (keyword == "priority")
        {
            std::string val;
            if (!(arg_stream >> val))
                data_api.failed_conversion(arg_stream,  "reputation: priority <missing_arg>");
            else if (val == "whitelist")
                table_api.add_option("priority", "whitelist");
            else if (val == "blacklist")
                table_api.add_option("priority", "blacklist");
            else
            {
                data_api.failed_conversion(arg_stream, "reputation: priority " + val);
            }
        }
        else if (keyword == "scan_local")
        {
            tmpval = table_api.add_option("scan_local", true);
        }
        else if(keyword == "shared_max_instances")
        {
            table_api.add_deleted_comment("shared_max_instances");
        }
        else if (keyword == "white")
        {
            std::string val;
            if (!(arg_stream >> val))
                data_api.failed_conversion(arg_stream,  "reputation: white <missing_arg>");
            else if (val == "unblack")
                table_api.add_option("white", "unblack");
            else if (val == "trust")
                table_api.add_option("white", "trust");
            else
            {
                data_api.failed_conversion(arg_stream, "reputation: white " + val);
            }
        }
        else if (keyword == "whitelist")
        {
            std::string file_name;
            if( arg_stream >> file_name)
            {
                tmpval = table_api.add_option("whitelist", file_name);
            }
            else
            {
                data_api.failed_conversion(arg_stream, "reputation: whitelist <missing_arg>");
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
    return new Reputation(c);
}

static const ConvertMap preprocessor_reputation =
{
    "reputation",
    ctor,
};

const ConvertMap* reputation_map = &preprocessor_reputation;
}

