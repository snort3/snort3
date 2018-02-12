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
// out_csv.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace output
{
namespace
{
class AlertCsv : public ConversionState
{
public:
    AlertCsv(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool AlertCsv::convert(std::istringstream& data_stream)
{
    std::string keyword;
    std::string val;
    bool retval = true;
    int limit;
    char c = '\0';

    table_api.open_top_level_table("alert_csv");

    if (!(data_stream >> keyword))
        return true;

    table_api.add_deleted_comment("<filename> can no longer be specific");

    if (!(data_stream >> keyword))
        return retval;

    table_api.add_diff_option_comment("csv", "fields");
    // parsing the format list.
    std::istringstream format(keyword);
    while (std::getline(format, val, ','))
    {
        bool tmpval = true;

        if (val == "default")
            table_api.add_deleted_comment("default");

        else if (val == "timestamp")
            tmpval = table_api.add_list("fields", "timestamp");

        else if (val == "msg")
            tmpval = table_api.add_list("fields", "msg");

        else if (val == "proto")
            tmpval = table_api.add_list("fields", "proto");

        else if (val == "ttl")
            tmpval = table_api.add_list("fields", "ttl");

        else if (val == "tos")
            tmpval = table_api.add_list("fields", "tos");

        else if (val == "trheader")
            tmpval = table_api.add_deleted_comment("trheader");

        else if (val == "dst")
        {
            table_api.add_diff_option_comment("dst", "dst_addr");
            tmpval = table_api.add_list("fields", "dst_addr");
        }
        else if (val == "src")
        {
            table_api.add_diff_option_comment("src", "src_addr");
            tmpval = table_api.add_list("fields", "src_addr");
        }
        else if (val == "sig_generator")
        {
            table_api.add_diff_option_comment("sig_generator", "gid");
            tmpval = table_api.add_list("fields", "gid");
        }
        else if (val == "sig_id")
        {
            table_api.add_diff_option_comment("sig_id", "sid");
            tmpval = table_api.add_list("fields", "sid");
        }
        else if (val == "sig_rev")
        {
            table_api.add_diff_option_comment("sig_rev", "rev");
            tmpval = table_api.add_list("fields", "rev");
        }
        else if (val == "srcport")
        {
            table_api.add_diff_option_comment("srcport", "src_port");
            tmpval = table_api.add_list("fields", "src_port");
        }
        else if (val == "dstport")
        {
            table_api.add_diff_option_comment("dstport", "dst_port");
            tmpval = table_api.add_list("fields", "dst_port");
        }
        else if (val == "ethsrc")
        {
            table_api.add_diff_option_comment("ethsrc", "eth_src");
            tmpval = table_api.add_list("fields", "eth_src");
        }
        else if (val == "ethdst")
        {
            table_api.add_diff_option_comment("ethdst", "eth_dst");
            tmpval = table_api.add_list("fields", "eth_dst");
        }
        else if (val == "ethlen")
        {
            table_api.add_diff_option_comment("ethlen", "eth_len");
            tmpval = table_api.add_list("fields", "eth_len");
        }
        else if (val == "ethtype")
        {
            table_api.add_diff_option_comment("ethtype", "eth_type");
            tmpval = table_api.add_list("fields", "eth_type");
        }
        else if (val == "tcpflags")
        {
            table_api.add_diff_option_comment("tcpflags", "tcp_flags");
            tmpval = table_api.add_list("fields", "tcp_flags");
        }
        else if (val == "tcpseq")
        {
            table_api.add_diff_option_comment("tcpseq", "tcp_seq");
            tmpval = table_api.add_list("fields", "tcp_seq");
        }
        else if (val == "tcpack")
        {
            table_api.add_diff_option_comment("tcpack", "tcp_ack");
            tmpval = table_api.add_list("fields", "tcp_ack");
        }
        else if (val == "tcplen")
        {
            table_api.add_diff_option_comment("tcplen", "tcp_len");
            tmpval = table_api.add_list("fields", "tcp_len");
        }
        else if (val == "tcpwindow")
        {
            table_api.add_diff_option_comment("tcpwindow", "tcp_win");
            tmpval = table_api.add_list("fields", "tcp_win");
        }
        else if (val == "dgmlen")
        {
            table_api.add_diff_option_comment("dgmlen", "pkt_len");
            tmpval = table_api.add_list("fields", "pkt_len");
        }

        else if (val == "id")
        {
            table_api.add_diff_option_comment("id", "ip_id");
            tmpval = table_api.add_list("fields", "ip_id");
        }
        else if (val == "iplen")
        {
            table_api.add_diff_option_comment("iplen", "ip_len");
            tmpval = table_api.add_list("fields", "ip_len");
        }
        else if (val == "icmptype")
        {
            table_api.add_diff_option_comment("icmptype", "icmp_type");
            tmpval = table_api.add_list("fields", "icmp_type");
        }
        else if (val == "icmpcode")
        {
            table_api.add_diff_option_comment("icmpcode", "icmp_code");
            tmpval = table_api.add_list("fields", "icmp_code");
        }
        else if (val == "icmpid")
        {
            table_api.add_diff_option_comment("icmpid", "icmp_id");
            tmpval = table_api.add_list("fields", "icmp_id");
        }
        else if (val == "icmpseq")
        {
            table_api.add_diff_option_comment("icmpseq", "icmp_seq");
            tmpval = table_api.add_list("fields", "icmp_seq");
        }
        else if (val == "udplength")
        {
            table_api.add_diff_option_comment("udplength", "udp_len");
            tmpval = table_api.add_list("fields", "udp_len");
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

    if (data_stream >> c)
    {
        if (limit <= 0)
            limit = 0;
        else if (c == 'K' || c == 'k')
            limit = (limit + 1023) / 1024;
        else if (c == 'G' || c == 'g')
            limit *= 1024;
    }
    else
        limit = (limit + 1024*1024 - 1) / (1024*1024);

    retval = table_api.add_option("limit", limit) && retval;
    retval = table_api.add_comment("limit now in MB, converted") && retval;
    retval = table_api.add_deleted_comment("units") && retval;
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

