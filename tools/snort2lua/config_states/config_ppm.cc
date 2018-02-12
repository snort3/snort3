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
// config_ppm.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class Ppm : public ConversionState
{
public:
    Ppm(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool Ppm::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string keyword;

    table_api.open_table("latency");
    table_api.add_diff_option_comment("ppm", "latency");

    while (data_stream >> keyword)
    {
        bool tmpval = true;
        bool popped_comma;

        if (keyword.back() == ',')
        {
            keyword.pop_back();
            popped_comma = true;
        }
        else
        {
            popped_comma = false;
        }

        if (keyword.empty())
            continue;

        if (keyword == "threshold")
        {
            table_api.add_diff_option_comment("threshold", "rule.suspend_threshold");
            table_api.open_table("rule");
            tmpval = parse_int_option("suspend_threshold", data_stream, false);
            table_api.close_table();
        }

        else if (keyword == "fastpath-expensive-packets")
        {
            table_api.add_diff_option_comment("fastpath-expensive-packets", "packet.fastpath");
            table_api.open_table("packet");
            tmpval = table_api.add_option("fastpath", true);
            table_api.close_table();
        }

        else if (keyword == "max-pkt-time")
        {
            table_api.add_diff_option_comment("max-pkt-time", "packet.max_time");
            table_api.open_table("packet");
            tmpval = parse_int_option("max_time", data_stream, false);
            table_api.close_table();
        }

        else if (keyword == "debug-pkts")
            table_api.add_deleted_comment("debug-pkts");

        else if (keyword == "max-rule-time")
        {
            table_api.add_diff_option_comment("max-rule-time", "rule.max_time");
            table_api.open_table("rule");
            tmpval = parse_int_option("max_time", data_stream, false);
            table_api.close_table();
        }

        else if (keyword == "suspend-expensive-rules")
        {
            table_api.add_diff_option_comment("suspend-expensive-rules", "rule.suspend");
            table_api.open_table("rule");
            tmpval = table_api.add_option("suspend", true);
            table_api.close_table();
        }

        else if (keyword == "suspend-timeout")
        {
            table_api.add_diff_option_comment("suspend-timeout", "max_suspend_time");
            table_api.open_table("rule");

            int opt;

            if (!(data_stream >> opt))
                tmpval = false;

            else
            {
                table_api.add_diff_option_comment("suspend-timeout", "max_suspend_time");
                table_api.add_comment("seconds changed to milliseconds");
                tmpval = table_api.add_option("max_suspend_time", opt * 1000);
            }

            table_api.close_table();
        }

        else if (keyword == "pkt-log")
        {
            table_api.add_diff_option_comment("pkt-log", "packet.action");
            table_api.open_table("packet");

            std::string opt1;
            std::string opt2;

            if (popped_comma)
                table_api.add_option("action", "log");

            else if (!(data_stream >> opt1))
                table_api.add_option("action", "log");

            else if (opt1.back() == ',')
            {
                opt1.pop_back();
                tmpval = table_api.add_option("action", opt1);
            }

            else if (!(data_stream >> opt2))
                tmpval = table_api.add_option("action", opt1);

            else
            {
                table_api.add_diff_option_comment("'both'", "'alert_and_log'");
                tmpval = table_api.add_option("action", "alert_and_log");
            }

            table_api.close_table();
        }

        else if (keyword == "rule-log")
        {
            table_api.add_diff_option_comment("rule-log", "rule.action");
            table_api.open_table("rule");

            std::string opt1;
            std::string opt2;

            if (!(data_stream >> opt1))
                tmpval = false;

            else if (opt1.back() == ',')
            {
                opt1.pop_back();
                tmpval = table_api.add_option("action", opt1);
            }

            else if (!(data_stream >> opt2))
                tmpval = table_api.add_option("action", opt1);

            else
            {
                table_api.add_diff_option_comment("'both'", "'alert_and_log'");
                tmpval = table_api.add_option("action", "alert_and_log");
            }

            table_api.close_table();
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

static ConversionState* ctor(Converter& c)
{ return new Ppm(c); }

static const ConvertMap config_ppm_api =
{
    "ppm",
    ctor,
};

const ConvertMap* ppm_map = &config_ppm_api;
} // namespace config

