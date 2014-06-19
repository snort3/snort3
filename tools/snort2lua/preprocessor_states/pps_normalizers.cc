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
// pps_normalizers.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>
#include <iomanip>

#include "conversion_state.h"
#include "converter.h"
#include "snort2lua_util.h"


/****************************
 *******  ICMP4 API *********
 ****************************/

static ConversionState* icmp4_ctor(Converter* cv)
{
    cv->open_table("normalize");
    cv->add_option_to_table("icmp4", true);
    cv->close_table();
    return nullptr;
}

static const ConvertMap preprocessor_norm_icmp4 = 
{
    "normalize_icmp4",
    icmp4_ctor,
};

const ConvertMap* normalizer_icmp4_map = &preprocessor_norm_icmp4;

/****************************
 *******  ICMP6 API *********
 ***************************/

static ConversionState* icmp6_ctor(Converter* cv)
{
    cv->open_table("normalize");
    cv->add_option_to_table("icmp6", true);
    cv->close_table();
    return nullptr;
}

static const ConvertMap preprocessor_norm_icmp6 = 
{
    "normalize_icmp6",
    icmp6_ctor,
};

const ConvertMap* normalizer_icmp6_map = &preprocessor_norm_icmp6;


/**************************
 *******  IP4 API *********
 **************************/

namespace {

class Ip4Normalizer : public ConversionState
{
public:
    Ip4Normalizer(Converter* cv)  : ConversionState(cv) {};
    virtual ~Ip4Normalizer() {};
    virtual bool convert(std::stringstream& data_stream);
};

} // namespace


bool Ip4Normalizer::convert(std::stringstream& data_stream)
{
    std::string keyword;
    bool retval = true;

    cv->open_table("normalize");
    cv->open_table("ip4");
    cv->add_option_to_table("base", true);

    while( data_stream >> keyword)
    {

        if(!keyword.compare("df"))
            retval = cv->add_option_to_table("df", true) && retval;

        else if(!keyword.compare("rf"))
            retval = cv->add_option_to_table("rf", true) && retval;
        
        else if(!keyword.compare("tos"))
            retval = cv->add_option_to_table("tos", true) && retval;
        
        else if(!keyword.compare("trim"))
            retval = cv->add_option_to_table("trim", true) && retval;

        else
            retval = false;
    }

    cv->close_table();
    cv->close_table();
    return retval;    
}

/*******  A P I ***********/

static ConversionState* ip4_ctor(Converter* cv)
{
    return new Ip4Normalizer(cv);
}

static const ConvertMap preprocessor_norm_ip4 = 
{
    "normalize_ip4",
    ip4_ctor,
};

const ConvertMap* normalizer_ip4_map = &preprocessor_norm_ip4;

/**************************
 *******  IP6 API *********
 **************************/

static ConversionState* ip6_ctor(Converter* cv)
{
    cv->open_table("normalize");
    cv->add_option_to_table("ip6", true);
    cv->close_table();
    return nullptr;
}

static const ConvertMap preprocessor_norm_ip6 = 
{
    "normalize_ip6",
    ip6_ctor,
};

const ConvertMap* normalizer_ip6_map = &preprocessor_norm_ip6;


/**************************
 *******  TCP API *********
 **************************/

namespace {

class TcpNormalizer : public ConversionState
{
public:
    TcpNormalizer(Converter* cv)  : ConversionState(cv) {};
    virtual ~TcpNormalizer() {};
    virtual bool convert(std::stringstream& data_stream);
private:
    bool set_base_w_comment(std::string);
    bool set_ecn_w_comment(std::string);
    bool set_trim_w_comment(std::string);

};

} // namespace

bool TcpNormalizer::set_ecn_w_comment(std::string comment)
{
    cv->add_comment_to_table("tcp normalizer: '" +
        comment + "'' is deprecated. use 'ecn' instead");
    return cv->add_option_to_table("ecn", true);
}

bool TcpNormalizer::set_base_w_comment(std::string comment)
{
    cv->add_comment_to_table("tcp normalizer: '" +
        comment + "'' is deprecated. use 'base' instead");
    return cv->add_option_to_table("base", true);
}

bool TcpNormalizer::set_trim_w_comment(std::string comment)
{
    cv->add_comment_to_table("tcp normalizer: '" +
        comment + "'' is deprecated. use 'trim' instead");
    return cv->add_option_to_table("trim", true);
}


bool TcpNormalizer::convert(std::stringstream& data_stream)
{
    std::string keyword;
    std::string value;
    bool retval = true;

    cv->open_table("normalize");
    cv->open_table("tcp");
    cv->add_option_to_table("base", true);

    while( data_stream >> keyword)
    {

        if(!keyword.compare("rsv"))
            retval = set_base_w_comment("rsv") && retval;
        
        else if(!keyword.compare("pad"))
            retval = set_base_w_comment("pad") && retval;

        else if(!keyword.compare("block"))
            retval = set_base_w_comment("block") && retval;

        else if(!keyword.compare("req_urg"))
            retval = set_base_w_comment("req_urg") && retval;

        else if(!keyword.compare("req_pay"))
            retval = set_base_w_comment("req_pay") && retval;

        else if(!keyword.compare("req_urp"))
            retval = set_base_w_comment("req_urp") && retval;
        
        else if(!keyword.compare("ips"))
            retval = cv->add_option_to_table("ips", true) && retval;
        
        else if(!keyword.compare("trim_syn"))
            retval = set_trim_w_comment("trim_syn") && retval;
        
        else if(!keyword.compare("trim_rst"))
            retval = set_trim_w_comment("trim_rst") && retval;
        
        else if(!keyword.compare("trim_win"))
            retval = set_trim_w_comment("trim_win") && retval;
        
        else if(!keyword.compare("trim_mss"))
            retval = set_trim_w_comment("trim_mss") && retval;
        
        else if(!keyword.compare("trim"))
            retval = cv->add_option_to_table("trim", true) && retval;

        else if(!keyword.compare("opts"))
            retval = cv->add_option_to_table("opts", true) && retval;

        else if(!keyword.compare("urp"))
            retval = cv->add_option_to_table("urp", true) && retval;

        else if(!keyword.compare("ecn"))
        {
            if (data_stream >> value)
                set_ecn_w_comment("ecn " + value);
            else
                retval = false;
        }

        else
            retval = false;
    }

    cv->close_table();
    cv->close_table();
    return retval;    
}

/*******  A P I ***********/

static ConversionState* tcp_ctor(Converter* cv)
{
    return new TcpNormalizer(cv);
}

static const ConvertMap preprocessor_norm_tcp = 
{
    "normalize_tcp",
    tcp_ctor,
};

const ConvertMap* normalizer_tcp_map = &preprocessor_norm_tcp;
