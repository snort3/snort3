//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
    virtual ~Ppm() { }
    virtual bool convert(std::istringstream& data_stream);
};
} // namespace

bool Ppm::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string keyword;

    table_api.open_table("ppm");

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

        if (!keyword.compare("threshold"))
            tmpval = parse_int_option("threshold", data_stream, false);

        else if (!keyword.compare("fastpath-expensive-packets"))
        {
            table_api.add_diff_option_comment("fastpath-expensive-packets",
                "fastpath_expensive_packets");
            tmpval = table_api.add_option("fastpath_expensive_packets", true);
        }
        else if (!keyword.compare("max-pkt-time"))
        {
            table_api.add_diff_option_comment("max-pkt-time", "max_pkt_time");
            tmpval = parse_int_option("max_pkt_time", data_stream, false);
        }
        else if (!keyword.compare("debug-pkts"))
        {
            table_api.add_deleted_comment("debug-pkts");
        }
        else if (!keyword.compare("max-rule-time"))
        {
            table_api.add_diff_option_comment("max-rule-time", "max_rule_time");
            tmpval = parse_int_option("max_rule_time", data_stream, false);
        }
        else if (!keyword.compare("suspend-expensive-rules"))
        {
            table_api.add_diff_option_comment("suspend-expensive-rules",
                "suspend_expensive_rules");
            tmpval = table_api.add_option("suspend_expensive_rules", true);
        }
        else if (!keyword.compare("suspend-timeout"))
        {
            table_api.add_diff_option_comment("suspend-timeout", "suspend_timeout");
            tmpval = parse_int_option("suspend_timeout", data_stream, false);
        }
        else if (!keyword.compare("pkt-log"))
        {
            table_api.add_diff_option_comment("pkt-log", "pkt_log");
            std::string opt1;
            std::string opt2;

            if (popped_comma)
                table_api.add_option("pkt_log", "log");

            else if (!(data_stream >> opt1))
                table_api.add_option("pkt_log", "log");

            else if (opt1.back() == ',')
            {
                opt1.pop_back();
                tmpval = table_api.add_option("pkt_log", opt1);
            }
            else if (!(data_stream >> opt2))
                tmpval = table_api.add_option("pkt_log", opt1);

            else
                tmpval = table_api.add_option("pkt_log", "both");
        }
        else if (!keyword.compare("rule-log"))
        {
            std::string opt1;
            std::string opt2;
            table_api.add_diff_option_comment("rule-log", "rule_log");

            if (!(data_stream >> opt1))
                tmpval = false;

            else if (opt1.back() == ',')
            {
                opt1.pop_back();
                tmpval = table_api.add_option("rule_log", opt1);
            }
            else if (!(data_stream >> opt2))
                tmpval = table_api.add_option("rule_log", opt1);

            else
                tmpval = table_api.add_option("rule_log", "both");
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

