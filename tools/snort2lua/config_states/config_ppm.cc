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
// pps_frag3_global.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "util/util.h"

namespace {

class Ppm : public ConversionState
{
public:
    Ppm(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~Ppm() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool Ppm::convert(std::istringstream& data_stream)
{

    bool retval = true;
    std::string keyword;
    bool test;

    ld->open_table("ppm");

    while(data_stream >> keyword)
    {
        bool tmpval = true;
        bool popped_comma;

        if(keyword.back() == ',')
        {
            keyword.pop_back();
            popped_comma = true;
        }
        else
        {
            popped_comma = false;
        }

        if(keyword.empty())
            continue;
        
        if(!keyword.compare("threshold"))
            tmpval = parse_int_option("threshold", data_stream);

        else if(!keyword.compare("fastpath-expensive-packets"))
        {
            ld->add_diff_option_comment("fastpath-expensive-packets", "fastpath_expensive_packets");
            tmpval = ld->add_option_to_table("fastpath_expensive_packets", true);
        }
        
        else if(!keyword.compare("max-pkt-time"))
        {
            ld->add_diff_option_comment("max-pkt-time", "max_pkt_time");
            tmpval = parse_int_option("max_pkt_time", data_stream);
        }
        
        else if(!keyword.compare("debug-pkts"))
        {
            ld->add_diff_option_comment("debug-pkts", "debug_pkts");
            tmpval = ld->add_option_to_table("debug_pkts", true);
        }
        
        else if(!keyword.compare("max-rule-time"))
        {
            ld->add_diff_option_comment("max-rule-time", "max_rule_time");
            tmpval = parse_int_option("max_rule_time", data_stream);
        }
        
        else if(!keyword.compare("suspend-expensive-rules"))
        {
            ld->add_diff_option_comment("suspend-expensive-rules", "suspend_expensive_rules");
            tmpval = ld->add_option_to_table("suspend_expensive_rules", true);
        }
        
        else if(!keyword.compare("suspend-timeout"))
        {
            ld->add_diff_option_comment("suspend-timeout", "suspend_timeout");
            tmpval = parse_int_option("suspend_timeout", data_stream);
        }
        
        else if(!keyword.compare("pkt-log"))
        {
            ld->add_diff_option_comment("pkt-log ", "pkt_log");
            std::string opt1;
            std::string opt2;

            if(popped_comma)
                ld->add_option_to_table("pkt_log", "log");

            else if (!(data_stream >> opt1))
                ld->add_option_to_table("pkt_log", "log");

            else if (opt1.back() == ',')
            {
                opt1.pop_back();
                tmpval = ld->add_option_to_table("pkt_log", opt1);
            }

            else if (!(data_stream >> opt2))
                tmpval = ld->add_option_to_table("pkt_log", opt1);

            else
                 tmpval = ld->add_option_to_table("pkt_log", "both");
        }
        
        else if(!keyword.compare("rule-log"))
        {
            std::string opt1;
            std::string opt2;
            popped_comma = false;
            ld->add_diff_option_comment("rule-log", "rule_log");

            if (!(data_stream >> opt1))
                tmpval = false;

            else if (opt1.back() == ',')
            {
                opt1.pop_back();
                tmpval = ld->add_option_to_table("rule_log", opt1);
            }

            else if (!(data_stream >> opt2))
                tmpval = ld->add_option_to_table("rule_log", opt1);

            else
                tmpval = ld->add_option_to_table("rule_log", "both");
        }
        
        else
            tmpval = false;

        if (retval)
            retval = tmpval;
    }
#if 0

pkt-log [log] [alert]

#endif

    return retval;    
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new Ppm(cv, ld);
}

static const ConvertMap config_ppm_api =
{
    "ppm",
    ctor,
};

const ConvertMap* ppm_map = &config_ppm_api;
