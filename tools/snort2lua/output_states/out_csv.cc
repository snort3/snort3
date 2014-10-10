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
#include "utils/s2l_util.h"

namespace output
{

namespace {

class AlertCsv : public ConversionState
{
public:
    AlertCsv(Converter& c) : ConversionState(c) {};
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


    table_api.open_top_level_table("alert_csv");

    if (!(data_stream >> keyword))
        return true;

    table_api.add_deleted_comment("<filename> can no longer be specific");


    if (!(data_stream >> keyword))
        return retval;


    // parsing the format list.
    std::istringstream format(keyword);
    while (std::getline(format, val, ','))
    {
        bool tmpval = true;

        if (!val.compare("default"))
            table_api.add_deleted_comment("default");

        else if (!val.compare("timestamp"))
            tmpval = table_api.add_list("csv", "timestamp");

        else if (!val.compare("msg"))
            tmpval = table_api.add_list("csv", "msg");

        else if (!val.compare("proto"))
            tmpval = table_api.add_list("csv", "proto");

        else if (!val.compare("dst"))
            tmpval = table_api.add_list("csv", "dst");

        else if (!val.compare("src"))
            tmpval = table_api.add_list("csv", "src");

        else if (!val.compare("ttl"))
            tmpval = table_api.add_list("csv", "ttl");

        else if (!val.compare("id"))
            tmpval = table_api.add_list("csv", "id");

        else if (!val.compare("tos"))
            tmpval = table_api.add_list("csv", "tos");

        else if (!val.compare("sig_generator"))
        {
            table_api.add_diff_option_comment("sig_generator", "gid");
            tmpval = table_api.add_list("csv", "gid");
        }

        else if (!val.compare("sid_id"))
        {
            table_api.add_diff_option_comment("sid_id", "sid");
            tmpval = table_api.add_list("csv", "sid");
        }

        else if (!val.compare("sig_rev"))
        {
            table_api.add_diff_option_comment("sig_rev", "rev");
            tmpval = table_api.add_list("csv", "rev");
        }

        else if (!val.compare("srcport"))
        {
            table_api.add_diff_option_comment("srcport", "src_port");
            tmpval = table_api.add_list("csv", "src_port");
        }

        else if (!val.compare("dstport"))
        {
            table_api.add_diff_option_comment("dstport", "dst_port");
            tmpval = table_api.add_list("csv", "dst_port");
        }

        else if (!val.compare("ethsrc"))
        {
            table_api.add_diff_option_comment("ethsrc", "eth_src");
            tmpval = table_api.add_list("csv", "eth_src");
        }

        else if (!val.compare("ethdst"))
        {
            table_api.add_diff_option_comment("ethdst", "eth_dst");
            tmpval = table_api.add_list("csv", "eth_dst");
        }

        else if (!val.compare("ethlen"))
        {
            table_api.add_diff_option_comment("ethlen", "eth_len");
            tmpval = table_api.add_list("csv", "eth_len");
        }

        else if (!val.compare("tcpflags"))
        {
            table_api.add_diff_option_comment("tcpflags", "tcp_flags");
            tmpval = table_api.add_list("csv", "tcp_flags");
        }

        else if (!val.compare("tcpseq"))
        {
            table_api.add_diff_option_comment("tcpseq", "tcp_seq");
            tmpval = table_api.add_list("csv", "tcp_seq");
        }

        else if (!val.compare("tcpack"))
        {
            table_api.add_diff_option_comment("tcpack", "tcp_ack");
            tmpval = table_api.add_list("csv", "tcp_ack");
        }

        else if (!val.compare("tcplen"))
        {
            table_api.add_diff_option_comment("tcplen", "tcp_len");
            tmpval = table_api.add_list("csv", "tcp_len");
        }

        else if (!val.compare("tcpwindow"))
        {
            table_api.add_diff_option_comment("tcpwindow", "tcp_win");
            tmpval = table_api.add_list("csv", "tcp_win");
        }

        else if (!val.compare("dgmlen"))
        {
            table_api.add_diff_option_comment("dgmlen", "dgm_len");
            tmpval = table_api.add_list("csv", "dgm_len");
        }

        else if (!val.compare("iplen"))
        {
            table_api.add_diff_option_comment("iplen", "ip_len");
            tmpval = table_api.add_list("csv", "ip_len");
        }

        else if (!val.compare("icmptype"))
        {
            table_api.add_diff_option_comment("icmptype", "icmp_type");
            tmpval = table_api.add_list("csv", "icmp_type");
        }

        else if (!val.compare("icmpcode"))
        {
            table_api.add_diff_option_comment("icmpcode", "icmp_code");
            tmpval = table_api.add_list("csv", "icmp_code");
        }

        else if (!val.compare("icmpid"))
        {
            table_api.add_diff_option_comment("icmpid", "icmp_id");
            tmpval = table_api.add_list("csv", "icmp_id");
        }

        else if (!val.compare("icmpseq"))
        {
            table_api.add_diff_option_comment("icmpseq", "icmp_seq");
            tmpval = table_api.add_list("csv", "icmp_seq");
        }

        else
        {
            tmpval = false;
        }

        if (!tmpval)
        {
            data_api.failed_conversion(data_stream, val);
            retval = false;
        }
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


    retval = table_api.add_option("limit", limit) && retval;
    retval = table_api.add_option("units", units) && retval;
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    c.get_table_api().open_top_level_table("alert_csv"); // in case there are no arguments
    c.get_table_api().close_table();
    return new AlertCsv(c);
}

static const ConvertMap alert_csv_api =
{
    "alert_csv",
    ctor,
};

const ConvertMap* alert_csv_map = &alert_csv_api;

} // namespace output
