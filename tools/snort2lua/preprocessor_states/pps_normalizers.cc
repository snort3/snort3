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
// pps_normalizers.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>
#include <iomanip>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

namespace preprocessors
{


template<const std::string *norm_option>
static ConversionState* norm_sans_options_ctor(Converter* /*cv*/, LuaData* ld)
{
    ld->open_table("normalize");
    ld->add_diff_option_comment("preprocessor normalize_" + *norm_option, *norm_option + " = <bool>");
    ld->add_option_to_table(*norm_option, true);
    ld->close_table();
    return nullptr;
}

/****************************
 *******  ICMP4 API *********
 ****************************/


static const std::string icmp4 = "icmp4";
static const ConvertMap preprocessor_norm_icmp4 =
{
    "normalize_icmp4",
    norm_sans_options_ctor<&icmp4>,
};

const ConvertMap* normalizer_icmp4_map = &preprocessor_norm_icmp4;

/****************************
 *******  ICMP6 API *********
 ***************************/

static const std::string icmp6 = "icmp6";
static const ConvertMap preprocessor_norm_icmp6 =
{
    "normalize_icmp6",
    norm_sans_options_ctor<&icmp6>,
};

const ConvertMap* normalizer_icmp6_map = &preprocessor_norm_icmp6;


/**************************
 *******  IP6 API *********
 **************************/

static const std::string ip6 = "ip6";
static const ConvertMap preprocessor_norm_ip6 =
{
    "normalize_ip6",
    norm_sans_options_ctor<&ip6>,
};

const ConvertMap* normalizer_ip6_map = &preprocessor_norm_ip6;

/**************************
 *******  IP4 API *********
 **************************/

namespace {

class Ip4Normalizer : public ConversionState
{
public:
    Ip4Normalizer(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~Ip4Normalizer() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace


bool Ip4Normalizer::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    ld->open_table("normalize");
    ld->open_table("ip4");
    ld->add_option_to_table("base", true);

    while (util::get_string(data_stream, keyword, " ,"))
    {
        bool tmpval = true;

        if(!keyword.compare("df"))
            tmpval = ld->add_option_to_table("df", true);

        else if(!keyword.compare("rf"))
            tmpval = ld->add_option_to_table("rf", true);
        
        else if(!keyword.compare("tos"))
            tmpval = ld->add_option_to_table("tos", true);
        
        else if(!keyword.compare("trim"))
            tmpval = ld->add_option_to_table("trim", true);

        else
            tmpval = false;

        if (retval && !tmpval)
            retval = false;
    }

    ld->close_table();
    ld->close_table();
    return retval;    
}

/*******  A P I ***********/

static ConversionState* ip4_ctor(Converter* cv, LuaData* ld)
{
    return new Ip4Normalizer(cv, ld);
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

namespace {

class TcpNormalizer : public ConversionState
{
public:
    TcpNormalizer(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~TcpNormalizer() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace


bool TcpNormalizer::convert(std::istringstream& data_stream)
{
    std::string keyword;
    std::string value;
    bool retval = true;

    ld->open_table("normalize");
    ld->open_table("tcp");
    ld->add_option_to_table("base", true);

    while (util::get_string(data_stream, keyword, " ,"))
    {
        bool tmpval = true;

        if(!keyword.compare("ips"))
            tmpval = ld->add_option_to_table("ips", true);
        
        else if(!keyword.compare("trim"))
            tmpval = ld->add_option_to_table("trim", true);

        else if(!keyword.compare("opts"))
            tmpval = ld->add_option_to_table("opts", true);

        else if(!keyword.compare("urp"))
            tmpval = ld->add_option_to_table("urp", true);

        else if(!keyword.compare("rsv"))
        {
            ld->add_diff_option_comment("rsv", "base");
            ld->add_option_to_table("base", true);
        }

        else if(!keyword.compare("pad"))
        {
            ld->add_diff_option_comment("pad", "base");
            ld->add_option_to_table("base", true);
        }

        else if(!keyword.compare("block"))
        {
            ld->add_diff_option_comment("block", "base");
            ld->add_option_to_table("base", true);
        }

        else if(!keyword.compare("req_urg"))
        {
            ld->add_diff_option_comment("req_urg", "base");
            ld->add_option_to_table("base", true);
        }

        else if(!keyword.compare("req_pay"))
        {
            ld->add_diff_option_comment("req_pay", "base");
            ld->add_option_to_table("base", true);
        }

        else if(!keyword.compare("req_urp"))
        {
            ld->add_diff_option_comment("req_urp", "base");
            ld->add_option_to_table("base", true);
        }
        
        else if(!keyword.compare("trim_syn"))
        {
            ld->add_diff_option_comment("trim_syn", "trim");
            tmpval = ld->add_option_to_table("trim", true);
        }
        
        else if(!keyword.compare("trim_rst"))
        {
            ld->add_diff_option_comment("trim_rst", "trim");
            tmpval = ld->add_option_to_table("trim", true);
        }
        
        else if(!keyword.compare("trim_win"))
        {
            ld->add_diff_option_comment("trim_win", "trim");
            tmpval = ld->add_option_to_table("trim", true);
        }
        
        else if(!keyword.compare("trim_mss"))
        {
            ld->add_diff_option_comment("trim_mss", "trim");
            tmpval = ld->add_option_to_table("trim", true);
        }

        else if(!keyword.compare("ecn"))
        {
            if (util::get_string(data_stream, value, " ,"))
                ld->add_option_to_table("ecn", value);
            else
                tmpval = false;
        }

        else if (!keyword.compare("allow"))
        {
            // loop until we break or reach end of stream
            while (util::get_string(data_stream, keyword, " ,"))
            {
                std::streamoff pos = data_stream.tellg();

                if (!keyword.compare("sack"))
                    ld->add_list_to_table("allow_names", "sack");

                else if (!keyword.compare("echo"))
                    ld->add_list_to_table("allow_names", "echo");

                else if (!keyword.compare("partial_order"))
                    ld->add_list_to_table("allow_names", "partial_order");

                else if (!keyword.compare("conn_count"))
                    ld->add_list_to_table("allow_names", "conn_count");

                else if (!keyword.compare("alt_checksum"))
                    ld->add_list_to_table("allow_names", "alt_checksum");

                else if (!keyword.compare("md5"))
                    ld->add_list_to_table("allow_names", "md5");

                else if (isdigit(keyword[0]))
                    ld->add_list_to_table("allow_codes", keyword);

                else
                {
                    data_stream.seekg(pos);
                    break;
                }
            }
        }

        else
            retval = false;

        if (retval && !tmpval)
            retval = false;
    }

    ld->close_table();
    ld->close_table();
    return retval;    
}

/*******  A P I ***********/

static ConversionState* tcp_ctor(Converter* cv, LuaData* ld)
{
    return new TcpNormalizer(cv, ld);
}

static const ConvertMap preprocessor_norm_tcp = 
{
    "normalize_tcp",
    tcp_ctor,
};

const ConvertMap* normalizer_tcp_map = &preprocessor_norm_tcp;

} // namespace preprocessors
