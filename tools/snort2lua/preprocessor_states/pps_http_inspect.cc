//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// pps_http_inspect.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>
#include <string>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
namespace
{
class HttpInspect : public ConversionState
{
public:
    HttpInspect(Converter& c) : ConversionState(c) { }
    virtual ~HttpInspect() { }
    virtual bool convert(std::istringstream& data);

private:
    bool add_decode_option(std::string opt_name,  std::istringstream& stream);
};
} // namespace

bool HttpInspect::convert(std::istringstream& data_stream)
{
    std::string keyword;

    // using this to keep track of any errors.  I want to convert as much
    // as possible while being aware something went wrong
    bool retval = true;

    if (data_stream >> keyword)
    {
        if (keyword.compare("global"))
        {
            data_api.failed_conversion(data_stream, "'global' keyword required");
            return false;
        }
    }
    table_api.open_table("http_global");
    table_api.add_diff_option_comment("http_inspect", "http_global");

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (!keyword.compare("compress_depth"))
            tmpval = parse_int_option("compress_depth", data_stream, false);

        else if (!keyword.compare("decompress_depth"))
            tmpval = parse_int_option("decompress_depth", data_stream, false);

        else if (!keyword.compare("detect_anomalous_servers"))
            tmpval = table_api.add_option("detect_anomalous_servers", true);

        else if (!keyword.compare("proxy_alert"))
            tmpval = table_api.add_option("proxy_alert", true);

        else if (!keyword.compare("max_gzip_mem"))
            tmpval = parse_int_option("max_gzip_mem", data_stream, false);

        else if (!keyword.compare("memcap"))
            tmpval = parse_int_option("memcap", data_stream, false);

        else if (!keyword.compare("chunk_length"))
            tmpval = parse_int_option("chunk_length", data_stream, false);

        else if (!keyword.compare("disabled"))
            table_api.add_deleted_comment("disabled");

        else if (!keyword.compare("b64_decode_depth"))
            tmpval = add_decode_option("b64_decode_depth", data_stream);

        else if (!keyword.compare("bitenc_decode_depth"))
            tmpval = add_decode_option("bitenc_decode_depth", data_stream);

        else if (!keyword.compare("max_mime_mem"))
            tmpval = add_decode_option("max_mime_mem", data_stream);

        else if (!keyword.compare("qp_decode_depth"))
            tmpval = add_decode_option("qp_decode_depth", data_stream);

        else if (!keyword.compare("uu_decode_depth"))
            tmpval = add_decode_option("uu_decode_depth", data_stream);

        else if (!keyword.compare("iis_unicode_map"))
        {
            std::string codemap;
            int code_page;

            if ( (data_stream >> codemap) &&
                (data_stream >> code_page))
            {
                table_api.open_table("unicode_map");
                tmpval = table_api.add_option("map_file", codemap);
                tmpval = table_api.add_option("code_page", code_page) && tmpval;
                table_api.close_table();
            }
            else
            {
                data_api.failed_conversion(data_stream, "iis_unicode_map <filename> <codemap>");
                retval = false;
            }
        }
        else
        {
            tmpval = false;
        }

        if (!tmpval)
        {
            data_api.failed_conversion(data_stream, keyword);
            retval = false;
        }
    }

    return retval;
}

bool HttpInspect::add_decode_option(std::string opt_name,  std::istringstream& stream)
{
    int val;

    if (stream >> val)
    {
        table_api.open_table("decode");
        table_api.add_option(opt_name, val);
        table_api.close_table();
        return true;
    }
    else
    {
        table_api.add_comment("snort.conf missing argument for " +
            opt_name + " <int>");
        return false;
    }
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new HttpInspect(c);
}

static const ConvertMap preprocessor_httpinspect =
{
    "http_inspect",
    ctor,
};

const ConvertMap* httpinspect_map = &preprocessor_httpinspect;
} // namespace preprocessors

