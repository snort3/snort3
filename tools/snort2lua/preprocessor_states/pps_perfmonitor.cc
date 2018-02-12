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
// pps_perfmonitor.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <string>
#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
namespace
{
class PerfMonitor : public ConversionState
{
public:
    PerfMonitor(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;

private:
    bool output_set = false;
};
} // namespace

bool PerfMonitor::convert(std::istringstream& data_stream)
{
    table_api.open_table("perf_monitor");

    bool retval =
        table_api.add_option("base", true) and
        table_api.add_option("cpu", true);

    std::string keyword;

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword == "flow")
            tmpval = table_api.add_option("flow", true);

        else if (keyword == "max")
            table_api.add_deleted_comment("max");

        else if (keyword == "events")
            table_api.add_deleted_comment("events");

        else if (keyword == "console")
        {
            table_api.add_diff_option_comment("console", "output = 'console'");
            table_api.add_diff_option_comment("console", "format = 'text'");
            if (!output_set)
            {
                tmpval = table_api.add_option("output", "console");
                tmpval &= table_api.add_option("format", "text");
                output_set = true;
            }
        }

        else if (keyword == "reset")
            table_api.add_deleted_comment("atexitonly: reset");

        else if (keyword == "atexitonly")
            table_api.add_deleted_comment("atexitonly");

        else if (keyword == "base-stats")
            table_api.add_deleted_comment("atexitonly: base-stats");

        else if (keyword == "flow-stats")
            table_api.add_deleted_comment("atexitonly: flow-stats");

        else if (keyword == "flow-ip-stats")
            table_api.add_deleted_comment("atexitonly: flow-ip-stats");

        else if (keyword == "events-stats")
            table_api.add_deleted_comment("atexitonly: events-stats");

        else if (keyword == "max_file_size")
            tmpval = parse_int_option("max_file_size", data_stream, false);

        else if (keyword == "file")
        {
            table_api.add_diff_option_comment("file", "output = 'file'");
            table_api.add_diff_option_comment("file", "format = 'csv'");
            if (!output_set)
            {
                tmpval = table_api.add_option("output", "file");
                tmpval &= table_api.add_option("format", "csv");
                output_set = true;
            }
            eat_option(data_stream);
        }

        else if (keyword == "snortfile")
        {
            table_api.add_diff_option_comment("snortfile", "output = 'file'");
            table_api.add_diff_option_comment("snortfile", "format = 'csv'");
            if (!output_set)
            {
                tmpval = table_api.add_option("output", "file");
                tmpval &= table_api.add_option("format", "csv");
                output_set = true;
            }
            eat_option(data_stream);
        }
        else if (keyword == "flow-file")
        {
            table_api.add_diff_option_comment("flow-file", "output = 'file'");
            table_api.add_diff_option_comment("flow-file", "format = 'csv'");
            if (!output_set)
            {
                tmpval = table_api.add_option("output", "file");
                tmpval &= table_api.add_option("format", "csv");
                output_set = true;
            }
            eat_option(data_stream);
        }
        else if (keyword == "flow-ip-file")
        {
            table_api.add_diff_option_comment("flow-ip-file", "output = 'file'");
            table_api.add_diff_option_comment("flow-ip-file", "format = 'csv'");
            if (!output_set)
            {
                tmpval = table_api.add_option("output", "file");
                tmpval &= table_api.add_option("format", "csv");
                output_set = true;
            }
            eat_option(data_stream);
        }
        else if (keyword == "accumulate")
        {
            table_api.add_deleted_comment("accumulate");
        }
        else if (keyword == "flow-ip")
        {
            table_api.add_diff_option_comment("flow-ip", "flow_ip");
            tmpval = table_api.add_option("flow_ip", true);
        }
        else if (keyword == "flow-ports")
        {
            table_api.add_diff_option_comment("flow-ports", "flow_ports");
            tmpval = parse_int_option("flow_ports", data_stream, false);
        }
        else if (keyword == "time")
        {
            table_api.add_diff_option_comment("time", "seconds");
            tmpval = parse_int_option("seconds", data_stream, false);
        }
        else if (keyword == "flow-ip-memcap")
        {
            table_api.add_diff_option_comment("flow-ip-memcap", "flow_ip_memcap");
            tmpval = parse_string_option("flow_ip_memcap", data_stream);
        }
        else if (keyword == "pktcnt")
        {
            table_api.add_diff_option_comment("pktcnt", "packets");
            tmpval = parse_int_option("packets", data_stream, false);
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
{
    return new PerfMonitor(c);
}

static const ConvertMap keyword_perfmonitor =
{
    "perfmonitor",
    ctor,
};

const ConvertMap* perfmonitor_map = &keyword_perfmonitor;
}

