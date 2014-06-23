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
// pps_perfmonitor.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <string>
#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "converter.h"
#include "snort2lua_util.h"

namespace {

class PerfMonitor : public ConversionState
{
public:
    PerfMonitor(Converter* cv)  : ConversionState(cv) {};
    virtual ~PerfMonitor() {};
    virtual bool convert(std::stringstream& data_stream);
private:
    bool parse_file_option(std::stringstream& data_stream,
                        std::string orig_name,
                        std::string option_name,
                        std::string new_file_name);
};

} // namespace

bool PerfMonitor::parse_file_option(std::stringstream& data_stream,
                                std::string orig_name,
                                std::string option_name,
                                std::string new_file_name)
{
    bool tmpval;

    cv->add_comment_to_table(orig_name + " deprecated. If '" + option_name + 
        " = true', Snort++ automatically prints to '" + new_file_name + "'");
    cv->add_diff_option_comment(orig_name, option_name + " = true");
    tmpval = cv->add_option_to_table(option_name, true);

    if (eat_option(data_stream)) // we no longer care about the file name.
        return tmpval;
    return false;
}

bool PerfMonitor::convert(std::stringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    cv->open_table("perf_monitor");

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (!keyword.compare("flow"))
            tmpval = cv->add_option_to_table("flow", true);

        else if (!keyword.compare("max"))
            tmpval = cv->add_option_to_table("max", true);

        else if (!keyword.compare("events"))
            tmpval = cv->add_option_to_table("events", true);

        else if (!keyword.compare("console"))
            tmpval = cv->add_option_to_table("console", true);

        else if (!keyword.compare("reset"))
            tmpval = cv->add_option_to_table("reset", true);

        else if (!keyword.compare("atexitonly"))
            cv->add_deprecated_comment("atexitonly");

        else if (!keyword.compare("base-stats"))
            cv->add_deprecated_comment("atexitonly: base-stats");

        else if (!keyword.compare("flow-stats"))
            cv->add_deprecated_comment("atexitonly: flow-stats");

        else if (!keyword.compare("flow-ip-stats"))
            cv->add_deprecated_comment("atexitonly: flow-ip-stats");

        else if (!keyword.compare("events-stats"))
            cv->add_deprecated_comment("atexitonly: events-stats");

        else if (!keyword.compare("max_file_size"))
            tmpval = parse_int_option("max_file_size", data_stream);

        else if (!keyword.compare("file"))
            parse_file_option(data_stream, "file",
                                "file", "perf_monitor.csv");

        else if (!keyword.compare("snortfile"))
            parse_file_option(data_stream, "snortfile",
                                "file", "perf_monitor.csv");

        else if (!keyword.compare("flow-file"))
            parse_file_option(data_stream, "flow-file",
                                "flow_file", "perf_monitor_flow.csv");

        else if (!keyword.compare("flow-ip-file"))
            parse_file_option(data_stream, "flow-ip-file",
                                "flow_ip_file", "perf_monitor_flow_ip.csv");

        else if (!keyword.compare("accumulate"))
        {
            cv->add_diff_option_comment("accumulate", "reset = false");
            tmpval = cv->add_option_to_table("reset", false);
        }

        else if (!keyword.compare("flow-ip"))
        {
            cv->add_diff_option_comment("flow-ip", "flow_ip");
            tmpval = cv->add_option_to_table("flow_ip", true);            
        }

        else if (!keyword.compare("flow-ports"))
        {
            cv->add_diff_option_comment("flow-ports", "flow_ports");
            tmpval = parse_int_option("flow_ports", data_stream);            
        }

        else if (!keyword.compare("time"))
        {
            cv->add_diff_option_comment("time", "seconds");
            tmpval = parse_int_option("seconds", data_stream);
        }

        else if (!keyword.compare("flow-ip-memcap"))
        {
            cv->add_diff_option_comment("flow-ip-memcap", "flow_ip_memcap");
            tmpval = parse_string_option("flow_ip_memcap", data_stream);
        }

        else if (!keyword.compare("pktcnt"))
        {
            cv->add_diff_option_comment("pktcnt", "packets");
            tmpval = parse_int_option("packets", data_stream);
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
    return new PerfMonitor(cv);
}

static const ConvertMap keyword_perfmonitor = 
{
    "perfmonitor",
    ctor,
};

const ConvertMap* perfmonitor_map = &keyword_perfmonitor;
