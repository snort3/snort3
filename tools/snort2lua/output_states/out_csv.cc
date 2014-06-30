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
// out_csv.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "util/util.h"

namespace output
{

namespace {

class AlertCsv : public ConversionState
{
public:
    AlertCsv(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~AlertCsv() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool AlertCsv::convert(std::istringstream& data_stream)
{
    std::string keyword;
    std::string val;
    bool retval = true;
    int limit;
    char c;
    std::string units;


    ld->open_top_level_table("alert_csv");

    if (!(data_stream >> keyword))
        return true;

    retval = ld->add_option_to_table("file", keyword);


    if (!(data_stream >> keyword))
        return retval;


    // parsing the format list.
    std::istringstream format(keyword);
    while (std::getline(format, val, ','))
    {
        std::string new_val = std::string();

        if (!val.compare("default"))
            ld->add_deprecated_comment("default");

        else if (!val.compare("timestamp"))
            new_val = "timestamp";

        else if (!val.compare("msg"))
            new_val = "msg";

        else if (!val.compare("sig_generator"))
            new_val = "gid";

        else if (!val.compare("sid_id"))
            new_val = "sid";

        else if (!val.compare("sig_rev"))
            new_val = "rev";

        else if (!val.compare("proto"))
            new_val = "proto";

        else if (!val.compare("src"))
            new_val = "src";

        else if (!val.compare("srcport"))
            new_val = "src_port";

        else if (!val.compare("dst"))
            new_val = "dst";

        else if (!val.compare("dstport"))
            new_val = "dst_port";

        else if (!val.compare("ethsrc"))
            new_val = "eth_src";

        else if (!val.compare("ethdst"))
            new_val = "eth_dst";

        else if (!val.compare("ethlen"))
            new_val = "eth_len";

        else if (!val.compare("tcpflags"))
            new_val = "tcp_flags";

        else if (!val.compare("tcpseq"))
            new_val = "tcp_seq";

        else if (!val.compare("tcpack"))
            new_val = "tcp_ack";

        else if (!val.compare("tcplen"))
            new_val = "tcp_len";

        else if (!val.compare("tcpwindow"))
            new_val = "tcp_win";

        else if (!val.compare("ttl"))
            new_val = "ttl";

        else if (!val.compare("tos"))
            new_val = "tos";

        else if (!val.compare("id"))
            new_val = "id";

        else if (!val.compare("dgmlen"))
            new_val = "dgm_len";

        else if (!val.compare("iplen"))
            new_val = "ip_len";

        else if (!val.compare("icmptype"))
            new_val = "icmp_type";

        else if (!val.compare("icmpcode"))
            new_val = "icmp_code";

        else if (!val.compare("icmpid"))
            new_val = "icmp_id";

        else if (!val.compare("icmpseq"))
            new_val = "icmp_seq";

        else
        {
            ld->add_comment_to_table("unkown format option: " + val);
            retval = false;
        }

        if (!new_val.empty())
        {
            if (val.compare(new_val))
                ld->add_diff_option_comment(val, new_val);

            if (!ld->add_list_to_table("csv", new_val))
                retval = false;
        }
    }

    if (!(data_stream >> limit))
        return retval;

    if (data_stream >> c)
    {
        if (c == 'K' || c == 'k')
            units = "K";
        else if (c == 'M' || c == 'm')
            units = "M";
        else if (c == 'G' || c == 'g')
            units = "G";
    }
    else
        units = "B";


    retval = ld->add_option_to_table("limit", limit) && retval;
    retval = ld->add_option_to_table("units", units) && retval;

    // If we read something, more data available and bad input
    if (data_stream >> keyword)
        retval = false;

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    ld->open_top_level_table("alert_csv"); // in case there are no arguments
    ld->close_table();
    return new AlertCsv(cv, ld);
}

static const ConvertMap alert_csv_api =
{
    "alert_csv",
    ctor,
};

const ConvertMap* alert_csv_map = &alert_csv_api;

} // namespace output
