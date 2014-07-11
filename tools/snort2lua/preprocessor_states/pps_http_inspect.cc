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
// pps_http_inspect.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>
#include <string>

#include "conversion_state.h"
#include "util/converter.h"
#include "util/util.h"

namespace preprocessors
{

namespace {

class HttpInspect : public ConversionState
{
public:
    HttpInspect(Converter* cv, LuaData* ld);
    virtual ~HttpInspect() {};
    virtual bool convert(std::istringstream& data);

private:
    bool add_decode_option(std::string opt_name,  std::istringstream& stream);
};

} // namespace


HttpInspect::HttpInspect(Converter* cv, LuaData* ld) : ConversionState(cv, ld)
{}

bool HttpInspect::convert(std::istringstream& data_stream)
{
    std::string keyword;

    // using this to keep track of any errors.  I want to convert as much 
    // as possible while being aware something went wrong
    bool retval = true;

    if(data_stream >> keyword)
    {
        if(keyword.compare("global"))
        {
            cv->log_error("preprocessor httpinspect: requires the 'global' keyword");
            return false;
        }
    }
    ld->open_table("http_inspect");



    while(data_stream >> keyword)
    {
        bool tmpval = true;

        if(!keyword.compare("compress_depth"))
            tmpval = parse_int_option("compress_depth", data_stream);

        else if(!keyword.compare("decompress_depth")) 
            tmpval = parse_int_option("decompress_depth", data_stream);

        else if(!keyword.compare("detect_anomalous_servers"))
            tmpval = ld->add_option_to_table("detect_anomalous_servers", true);

        else if(!keyword.compare("proxy_alert"))
            tmpval = ld->add_option_to_table("proxy_alert", true);

        else if(!keyword.compare("max_gzip_mem"))
            tmpval = parse_int_option("max_gzip_mem", data_stream);
        
        else if(!keyword.compare("memcap"))
            tmpval = parse_int_option("memcap", data_stream);

        else if(!keyword.compare("chunk_length"))
            tmpval = parse_int_option("chunk_length", data_stream);
        
        else if(!keyword.compare("disabled"))
            ld->add_deprecated_comment("disabled");

        else if(!keyword.compare("b64_decode_depth"))
            tmpval = add_decode_option("b64_decode_depth", data_stream);

        else if(!keyword.compare("bitenc_decode_depth"))
            tmpval = add_decode_option("bitenc_decode_depth", data_stream);

        else if(!keyword.compare("max_mime_mem"))
            tmpval = add_decode_option("max_mime_mem", data_stream);
        
        else if(!keyword.compare("qp_decode_depth"))
            tmpval = add_decode_option("qp_decode_depth", data_stream);

        else if(!keyword.compare("uu_decode_depth"))
            tmpval = add_decode_option("uu_decode_depth", data_stream);

        else if(!keyword.compare("iis_unicode_map"))
        {
            std::string codemap;
            int code_page;

            if( (data_stream >> codemap) &&
                (data_stream >> code_page))
            {
                ld->open_table("unicode_map");
                tmpval = ld->add_option_to_table("map_file", codemap);
                tmpval = ld->add_option_to_table("code_page", code_page) && tmpval;
                ld->close_table();
            }
            else
            {
                ld->add_comment_to_table("snort.conf missing argument for "
                    "iis_unicode_map <filename> <codemap>");
                tmpval = false;
            }
        }

        else
        {
            retval = false;
        }

        if (retval && !tmpval)
            retval = false;
    }

    return retval;    
}

bool HttpInspect::add_decode_option(std::string opt_name,  std::istringstream& stream)
{
    int val;

    if (stream >> val)
    {
        ld->open_table("decode");
        ld->add_option_to_table(opt_name, val);
        ld->close_table();
        return true;
    }
    else
    {
        ld->add_comment_to_table("snort.conf missing argument for " +
            opt_name + " <int>");
        return false;
    }
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new HttpInspect(cv, ld);
}

static const ConvertMap preprocessor_httpinspect = 
{
    "http_inspect",
    ctor,
};

const ConvertMap* httpinspect_map = &preprocessor_httpinspect;

} // namespace preprocessors
