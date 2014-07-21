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
// out_csv.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

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
    char c = '\0';
    std::string units = "B";


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
        bool tmpval = true;

        if (!val.compare("default"))
            ld->add_deleted_comment("default");

        else if (!val.compare("timestamp"))
            tmpval = ld->add_list_to_table("csv", "timestamp");

        else if (!val.compare("msg"))
            tmpval = ld->add_list_to_table("csv", "msg");

        else if (!val.compare("proto"))
            tmpval = ld->add_list_to_table("csv", "proto");

        else if (!val.compare("dst"))
            tmpval = ld->add_list_to_table("csv", "dst");

        else if (!val.compare("src"))
            tmpval = ld->add_list_to_table("csv", "src");

        else if (!val.compare("ttl"))
            tmpval = ld->add_list_to_table("csv", "ttl");

        else if (!val.compare("id"))
            tmpval = ld->add_list_to_table("csv", "id");

        else if (!val.compare("tos"))
            tmpval = ld->add_list_to_table("csv", "tos");

        else if (!val.compare("sig_generator"))
        {
            ld->add_diff_option_comment("sig_generator", "gid");
            tmpval = ld->add_list_to_table("csv", "gid");
        }

        else if (!val.compare("sid_id"))
        {
            ld->add_diff_option_comment("sid_id", "sid");
            tmpval = ld->add_list_to_table("csv", "sid");
        }

        else if (!val.compare("sig_rev"))
        {
            ld->add_diff_option_comment("sig_rev", "rev");
            tmpval = ld->add_list_to_table("csv", "rev");
        }

        else if (!val.compare("srcport"))
        {
            ld->add_diff_option_comment("srcport", "src_port");
            tmpval = ld->add_list_to_table("csv", "src_port");
        }

        else if (!val.compare("dstport"))
        {
            ld->add_diff_option_comment("dstport", "dst_port");
            tmpval = ld->add_list_to_table("csv", "dst_port");
        }

        else if (!val.compare("ethsrc"))
        {
            ld->add_diff_option_comment("ethsrc", "eth_src");
            tmpval = ld->add_list_to_table("csv", "eth_src");
        }

        else if (!val.compare("ethdst"))
        {
            ld->add_diff_option_comment("ethdst", "eth_dst");
            tmpval = ld->add_list_to_table("csv", "eth_dst");
        }

        else if (!val.compare("ethlen"))
        {
            ld->add_diff_option_comment("ethlen", "eth_len");
            tmpval = ld->add_list_to_table("csv", "eth_len");
        }

        else if (!val.compare("tcpflags"))
        {
            ld->add_diff_option_comment("tcpflags", "tcp_flags");
            tmpval = ld->add_list_to_table("csv", "tcp_flags");
        }

        else if (!val.compare("tcpseq"))
        {
            ld->add_diff_option_comment("tcpseq", "tcp_seq");
            tmpval = ld->add_list_to_table("csv", "tcp_seq");
        }

        else if (!val.compare("tcpack"))
        {
            ld->add_diff_option_comment("tcpack", "tcp_ack");
            tmpval = ld->add_list_to_table("csv", "tcp_ack");
        }

        else if (!val.compare("tcplen"))
        {
            ld->add_diff_option_comment("tcplen", "tcp_len");
            tmpval = ld->add_list_to_table("csv", "tcp_len");
        }

        else if (!val.compare("tcpwindow"))
        {
            ld->add_diff_option_comment("tcpwindow", "tcp_win");
            tmpval = ld->add_list_to_table("csv", "tcp_win");
        }

        else if (!val.compare("dgmlen"))
        {
            ld->add_diff_option_comment("dgmlen", "dgm_len");
            tmpval = ld->add_list_to_table("csv", "dgm_len");
        }

        else if (!val.compare("iplen"))
        {
            ld->add_diff_option_comment("iplen", "ip_len");
            tmpval = ld->add_list_to_table("csv", "ip_len");
        }

        else if (!val.compare("icmptype"))
        {
            ld->add_diff_option_comment("icmptype", "icmp_type");
            tmpval = ld->add_list_to_table("csv", "icmp_type");
        }

        else if (!val.compare("icmpcode"))
        {
            ld->add_diff_option_comment("icmpcode", "icmp_code");
            tmpval = ld->add_list_to_table("csv", "icmp_code");
        }

        else if (!val.compare("icmpid"))
        {
            ld->add_diff_option_comment("icmpid", "icmp_id");
            tmpval = ld->add_list_to_table("csv", "icmp_id");
        }

        else if (!val.compare("icmpseq"))
        {
            ld->add_diff_option_comment("icmpseq", "icmp_seq");
            tmpval = ld->add_list_to_table("csv", "icmp_seq");
        }

        else
        {
            ld->add_comment_to_table("unkown format option: " + val);
            retval = false;
        }

        if (retval && !tmpval)
            retval = false;
    }

    if (!(data_stream >> limit))
        return retval;

    // default units is bytes.  set above
    if (data_stream >> c)
    {
        if (c == 'K' || c == 'k')
            units = "K";
        else if (c == 'M' || c == 'm')
            units = "M";
        else if (c == 'G' || c == 'g')
            units = "G";
    }


    retval = ld->add_option_to_table("limit", limit) && retval;
    retval = ld->add_option_to_table("units", units) && retval;
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
