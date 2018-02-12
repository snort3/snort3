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
// pps_normalizers.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>
#include <iomanip>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
template<const std::string* norm_option>
static ConversionState* norm_sans_options_ctor(Converter& c)
{
    c.get_table_api().open_table("normalizer");
    c.get_table_api().add_diff_option_comment("preprocessor normalize_" + *norm_option,
        *norm_option + " = <bool>");
    c.get_table_api().add_option(*norm_option, true);
    c.get_table_api().close_table();
    return nullptr;
}

/****************************
 *******  ICMP4 API *********
 ****************************/

static const std::string icmp4 = "icmp4";
static const ConvertMap preprocessor_norm_icmp4 =
{
    "normalize_icmp4",
    norm_sans_options_ctor<& icmp4>,
};

const ConvertMap* normalizer_icmp4_map = &preprocessor_norm_icmp4;

/****************************
 *******  ICMP6 API *********
 ***************************/

static const std::string icmp6 = "icmp6";
static const ConvertMap preprocessor_norm_icmp6 =
{
    "normalize_icmp6",
    norm_sans_options_ctor<& icmp6>,
};

const ConvertMap* normalizer_icmp6_map = &preprocessor_norm_icmp6;

/**************************
 *******  IP6 API *********
 **************************/

static const std::string ip6 = "ip6";
static const ConvertMap preprocessor_norm_ip6 =
{
    "normalize_ip6",
    norm_sans_options_ctor<& ip6>,
};

const ConvertMap* normalizer_ip6_map = &preprocessor_norm_ip6;

/**************************
 *******  IP4 API *********
 **************************/

namespace
{
class Ip4Normalizer : public ConversionState
{
public:
    Ip4Normalizer(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool Ip4Normalizer::convert(std::istringstream& data_stream)
{
    std::string keyword;

    table_api.open_table("normalizer");
    table_api.open_table("ip4");

    while (util::get_string(data_stream, keyword, " ,"))
    {
        if (keyword == "df")
            table_api.add_option("df", true);

        else if (keyword == "rf")
            table_api.add_option("rf", true);

        else if (keyword == "tos")
            table_api.add_option("tos", true);

        else if (keyword == "trim")
            table_api.add_option("trim", true);

        else
            data_api.failed_conversion(data_stream, keyword);
    }

    table_api.close_table();
    table_api.close_table();
    return true;
}

/*******  A P I ***********/

static ConversionState* ip4_ctor(Converter& c)
{
    c.get_table_api().open_table("normalizer");
    c.get_table_api().open_table("ip4");
    c.get_table_api().close_table();
    c.get_table_api().close_table();
    return new Ip4Normalizer(c);
}

static const ConvertMap preprocessor_norm_ip4 =
{
    "normalize_ip4",
    ip4_ctor,
};

const ConvertMap* normalizer_ip4_map = &preprocessor_norm_ip4;

/**************************
 *******  TCP API *********
 **************************/

namespace
{
class TcpNormalizer : public ConversionState
{
public:
    TcpNormalizer(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool TcpNormalizer::convert(std::istringstream& data_stream)
{
    std::string keyword;
    std::string value;
    bool retval = true;

    table_api.open_table("normalizer");
    table_api.open_table("tcp");

    while (util::get_string(data_stream, keyword, " ,"))
    {
        if (keyword == "ips")
            table_api.add_option("ips", true);

        else if (keyword == "trim")
            table_api.add_option("trim", true);

        else if (keyword == "opts")
            table_api.add_option("opts", true);

        else if (keyword == "urp")
            table_api.add_option("urp", true);

        else if (keyword == "rsv")
            table_api.add_option("rsv", true);

        else if (keyword == "pad")
            table_api.add_option("pad", true);

        else if (keyword == "block")
            table_api.add_option("block", true);

        else if (keyword == "req_urg")
            table_api.add_option("req_urg", true);

        else if (keyword == "req_pay")
            table_api.add_option("req_pay", true);

        else if (keyword == "req_urp")
            table_api.add_option("req_urp", true);

        else if (keyword == "trim_syn")
            table_api.add_option("trim_syn", true);

        else if (keyword == "trim_rst")
            table_api.add_option("trim_rst", true);

        else if (keyword == "trim_win")
            table_api.add_option("trim_win", true);

        else if (keyword == "trim_mss")
            table_api.add_option("trim_mss", true);

        else if (keyword == "ftp" )
            table_api.add_deleted_comment(keyword);

        else if (keyword == "ecn")
        {
            if (util::get_string(data_stream, value, " ,"))
                table_api.add_option("ecn", value);
            else
                data_api.failed_conversion(data_stream, "ecn[, ]missing_argument");
        }
        else if (keyword == "allow")
        {
            // loop until we break or reach end of stream
            while (util::get_string(data_stream, keyword, " ,"))
            {
                std::streamoff pos = data_stream.tellg();

                if (keyword == "sack")
                    table_api.add_list("allow_names", "sack");

                else if (keyword == "echo")
                    table_api.add_list("allow_names", "echo");

                else if (keyword == "partial_order")
                    table_api.add_list("allow_names", "partial_order");

                else if (keyword == "conn_count")
                    table_api.add_list("allow_names", "conn_count");

                else if (keyword == "alt_checksum")
                    table_api.add_list("allow_names", "alt_checksum");

                else if (keyword == "md5")
                    table_api.add_list("allow_names", "md5");

                else if (isdigit(keyword[0]))
                    table_api.add_list("allow_codes", keyword);

                else
                {
                    data_stream.clear();
                    data_stream.seekg(pos);
                    break;
                }
            }
        }
        else
        {
            data_api.failed_conversion(data_stream, keyword);
            retval = false;
        }
    }

    table_api.close_table();
    table_api.close_table();
    return retval;
}

/*******  A P I ***********/

static ConversionState* tcp_ctor(Converter& c)
{
    c.get_table_api().open_table("normalizer");
    c.get_table_api().open_table("tcp");
    c.get_table_api().close_table();
    c.get_table_api().close_table();
    return new TcpNormalizer(c);
}

static const ConvertMap preprocessor_norm_tcp =
{
    "normalize_tcp",
    tcp_ctor,
};

const ConvertMap* normalizer_tcp_map = &preprocessor_norm_tcp;
} // namespace preprocessors

