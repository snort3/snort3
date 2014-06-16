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
// http_inspect.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>
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
    bool add_decode_option(std::string opt_name,  std::stringstream& stream);
    bool missing_arg_error(std::string error_string);
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

    // using this to keep track of any errors.  I want to convert as much 
    // as possible while being aware something went wrong
    bool retval = true;

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
            retval = parse_int_option("compress_depth", data_stream) && retval;

        else if(!keyword.compare("decompress_depth")) 
            retval = parse_int_option("decompress_depth", data_stream) && retval;

        else if(!keyword.compare("detect_anomalous_servers"))
            converter->add_option_to_table("detect_anomalous_servers", true);

        else if(!keyword.compare("proxy_alert"))
            converter->add_option_to_table("proxy_alert", true);

        else if(!keyword.compare("max_gzip_mem"))
            retval = parse_int_option("max_gzip_mem", data_stream) && retval;
        
        else if(!keyword.compare("memcap"))
            retval = parse_int_option("memcap", data_stream) && retval;
        
        else if(!keyword.compare("disabled"))
            converter->add_comment_to_table("'disabled' is deprecated");

        else if(!keyword.compare("b64_decode_depth"))
            retval = add_decode_option("b64_decode_depth", data_stream) && retval;

        else if(!keyword.compare("bitenc_decode_depth"))
            retval = add_decode_option("bitenc_decode_depth", data_stream) && retval;

        else if(!keyword.compare("max_mime_mem"))
            retval = add_decode_option("max_mime_mem", data_stream) && retval;
        
        else if(!keyword.compare("qp_decode_depth"))
            retval = add_decode_option("qp_decode_depth", data_stream) && retval;

        else if(!keyword.compare("uu_decode_depth"))
            retval = add_decode_option("uu_decode_depth", data_stream) && retval;

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


        else
        {
            converter->log_error("'preprocessor http_inspect: global' --> Invalid argument!!");
            retval = false;
        }
    }

    return retval;    
}

bool HttpInspect::add_decode_option(std::string opt_name,  std::stringstream& stream)
{
    int val;

    if (stream >> val)
    {
        converter->open_table("decode");
        converter->add_option_to_table(opt_name, val);
        converter->close_table();
        return true;
    }
    else
    {
        missing_arg_error(opt_name + " <int>");
        return false;
    }
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
