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
// config.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>
#include <iomanip>
#include <string>

#include "conversion_state.h"
#include "converter.h"
#include "snort2lua_util.h"

namespace {

class HttpInspect : public ConversionState
{
public:
    HttpInspect(Converter* cv);
    virtual ~HttpInspect() {};
    virtual bool convert(std::stringstream& data);

private:
    void add_decode_option(std::string opt_name, int val);
    bool missing_arg_error(std::string error_string);

    bool first_line;
    bool correct_keyword;
};

} // namespace


bool HttpInspect::missing_arg_error(std::string arg)
{
    converter->add_comment_to_table("snort.conf missing argument for " + arg);
    return false;
}

HttpInspect::HttpInspect(Converter* cv)  : ConversionState(cv)
{}

bool HttpInspect::convert(std::stringstream& data_stream)
{
    std::string keyword;
    std::string s_value;
    int i_value;

    bool retval = true;;

    if(data_stream >> keyword)
    {
        if(keyword.compare("global"))
        {
            converter->log_error("preprocessor httpinspect: requires the 'global' keyword");
            return false;
        }
    }
    converter->open_table("http_inspect");



    while(data_stream >> keyword)
    {
        if(!keyword.compare("compress_depth"))
        {
            if(data_stream >> i_value)
                converter->add_option_to_table("compress_depth", i_value);
            else
                retval = missing_arg_error("compress_depth <int>");
        }
        
        else if(!keyword.compare("decompress_depth")) 
        {
            if(data_stream >> i_value)
                converter->add_option_to_table("decompress_depth", i_value);
            else
                retval = missing_arg_error("decompress_depth <int>");
        }

        else if(!keyword.compare("detect_anomalous_servers"))
        {
            converter->add_option_to_table("detect_anomalous_servers", true);
        }

        else if(!keyword.compare("iis_unicode_map"))
        {
            std::string codemap;
            if( (data_stream >> s_value) &&
                (data_stream >> i_value))
            {
                converter->open_table("unicode_map");
                converter->add_option_to_table("map_file", s_value);
                converter->add_option_to_table("code_page", i_value);
                converter->close_table();
            }
            else
            {
                retval = missing_arg_error("iis_unicode_map <filename> <codemap>");
            }
        }
        else if(!keyword.compare("proxy_alert"))
        {
            converter->add_option_to_table("proxy_alert", true);
        }

        else if(!keyword.compare("max_gzip_mem"))
        {
            if(data_stream >> i_value)
                converter->add_option_to_table("max_gzip_mem", i_value);
            else
                retval = missing_arg_error("max_gzip_mem <int>");
        }
        
        else if(!keyword.compare("memcap"))
        {
            if(data_stream >> i_value)
                converter->add_option_to_table("memcap", i_value);
            else
                retval = missing_arg_error("memcap <int>");
        }
        
        else if(!keyword.compare("disabled"))
        {
            converter->add_comment_to_table("the option 'disabled' is deprecated");
        }
        
        else if(!keyword.compare("b64_decode_depth"))
        {
            if(data_stream >> i_value)
                add_decode_option("b64_decode_depth", i_value);
            else
                retval = missing_arg_error("b64_decode_depth <int>");
        }

        else if(!keyword.compare("bitenc_decode_depth"))
        {
            if(data_stream >> i_value)
                add_decode_option("bitenc_decode_depth", i_value);
            else
                retval = missing_arg_error("b64_decode_depth <int>");
        }
        else if(!keyword.compare("max_mime_mem"))
        {
            if(data_stream >> i_value)
                add_decode_option("max_mime_mem", i_value);
            else
                retval = missing_arg_error("max_mime_mem <int>");
        }

        else if(!keyword.compare("qp_decode_depth"))
        {
            if(data_stream >> i_value)
                add_decode_option("qp_decode_depth", i_value);
            else
                retval = missing_arg_error("qp_decode_depth <int>");
        }

        else if(!keyword.compare("uu_decode_depth"))
        {
            if(data_stream >> i_value)
                add_decode_option("uu_decode_depth", i_value);
            else
                retval = missing_arg_error("uu_decode_depth <int>");
        }

        else
        {
            converter->log_error("'preprocessor http_inspect: global' --> Invalid argument!!");
            retval = false;
        }
    }

    return retval;    
}


void HttpInspect::add_decode_option(std::string opt_name, int val)
{
    converter->open_table("decode");
    converter->add_option_to_table(opt_name, val);
    converter->close_table();
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv)
{
    return new HttpInspect(cv);
}

static const ConvertMap preprocessor_httpinspect = 
{
    "http_inspect",
    ctor,
};

const ConvertMap* httpinspect_map = &preprocessor_httpinspect;
