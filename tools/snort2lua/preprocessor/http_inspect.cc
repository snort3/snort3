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
    virtual bool convert(std::stringstream& data, std::ofstream&);

private:
    bool first_line;
    bool correct_keyword;
};

} // namespace


HttpInspect::HttpInspect(Converter* cv)  : ConversionState(cv)
{
    first_line = true;
}

bool HttpInspect::convert(std::stringstream& data_stream, std::ofstream&)
{
    std::string keyword;
    std::string value;
    bool retval = true;;

    if (first_line)
    {
        if(data_stream >> keyword)
        {
            if(keyword.compare("global"))
            {
                converter->log_error("preprocessor httpinspect: requires the 'global' keyword");
                return false;
            }
        }
        first_line = false;
        converter->open_table("http_inspect");
    }



    while(data_stream >> keyword)
    {
        if(!keyword.compare("compress_depth"))
        {
            if(data_stream >> value)
            {
                int c_depth = std::stoi(value);
                converter->add_option_to_table("compress_depth", c_depth);
            }
            else
            {
                converter->log_error("unable to find argument for 'preprocessor http_inspect: global compress_depth");
                retval = false;
            }
        }
        else if(!keyword.compare("decompress_depth")) 
        {
            if(data_stream >> value)
            {
                int c_depth = std::stoi(value);
                converter->add_option_to_table("decompress_depth", c_depth);
            }
            else
            {
                converter->log_error("unable to find argument for 'preprocessor http_inspect: global compress_depth");
                retval = false;
            }
        }
        else if(!keyword.compare("detect_anomalous_servers")) {}
        else if(!keyword.compare("iis_unicode_map"))
        {
            std::string codemap;
            if( (data_stream >> value) &&
                (data_stream >> codemap))
            {
                int code_map_i = std::stoi(codemap, nullptr);
                converter->open_table("unicode_map");
                converter->add_option_to_table("map_file", value);
                converter->add_option_to_table("code_page", code_map_i);
                converter->close_table();
            }
            else
            {
                converter->log_error("Invalid argument: 'preprocessor http_inspect: global .. unicode_map");
                retval = false;
            }
        }
        else if(!keyword.compare("proxy_alert")) {}
        else if(!keyword.compare("max_gzip_mem")) {}
        else if(!keyword.compare("memcap")) {}
        else if(!keyword.compare("disabled")) {}
        else if(!keyword.compare("b64_decode_depth"))
        {
            if(data_stream >> value)
            {
                int c_depth = std::stoi(value);
                converter->add_option_to_table("b64_decode_depth", c_depth);
            }
            else
            {
                converter->log_error("unable to find argument for 'preprocessor http_inspect: global b64_decode_depth");
                retval = false;
            }
        }
        else if(!keyword.compare("bitenc_decode_depth"))
        {
            if(data_stream >> value)
            {
                int c_depth = std::stoi(value);
                converter->add_option_to_table("bitenc_decode_depth", c_depth);
            }
            else
            {
                converter->log_error("unable to find argument for 'preprocessor http_inspect: global b64_decode_depth");
                retval = false;
            }
        }
        else if(!keyword.compare("max_mime_mem"))
        {
            if(data_stream >> value)
            {
                int c_depth = std::stoi(value);
                converter->add_option_to_table("max_mime_mem", c_depth);
            }
            else
            {
                converter->log_error("unable to find argument for 'preprocessor http_inspect: global b64_decode_depth");
                retval = false;
            }
        }
        else if(!keyword.compare("qp_decode_depth"))
        {
            if(data_stream >> value)
            {
                int c_depth = std::stoi(value);
                converter->add_option_to_table("qp_decode_depth", c_depth);
            }
            else
            {
                converter->log_error("unable to find argument for 'preprocessor http_inspect: global b64_decode_depth");
                retval = false;
            }
        }
        else if(!keyword.compare("uu_decode_depth"))
        {
            if(data_stream >> value)
            {
                int c_depth = std::stoi(value);
                converter->add_option_to_table("uu_decode_depth", c_depth);
            }
            else
            {
                converter->log_error("unable to find argument for 'preprocessor http_inspect: global b64_decode_depth");
                retval = false;
            }
        }
        else
        {
            converter->log_error("unknown word");
        }
    }

    return retval;    
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
