//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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
// pps_nhttp_inspect.cc author Bhagya Tholpady <bbantwal@cisco.com>

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
    bool convert(std::istringstream& data) override;
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
        if (keyword != "global")
        {
            data_api.failed_conversion(data_stream, "'global' keyword required");
            return false;
        }
    }
    table_api.open_table("http_inspect");

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword == "compress_depth")
            parse_deleted_option("compress_depth", data_stream);

        else if (keyword == "decompress_depth")
            parse_deleted_option("decompress_depth", data_stream);

        else if (keyword == "detect_anomalous_servers")
            table_api.add_deleted_comment("detect_anomalous_servers");

        else if (keyword == "proxy_alert")
            table_api.add_deleted_comment("proxy_alert");

        else if (keyword == "max_gzip_mem")
            parse_deleted_option("max_gzip_mem", data_stream);

        else if (keyword == "memcap")
            parse_deleted_option("memcap", data_stream);

        else if (keyword == "disabled")
            table_api.add_deleted_comment("disabled");

        else if (keyword == "b64_decode_depth")
            parse_deleted_option("b64_decode_depth", data_stream);

        else if (keyword == "bitenc_decode_depth")
            parse_deleted_option("bitenc_decode_depth", data_stream);

        else if (keyword == "max_mime_mem")
            parse_deleted_option("max_mime_mem", data_stream);

        else if (keyword == "qp_decode_depth")
            parse_deleted_option("qp_decode_depth", data_stream);

        else if (keyword == "uu_decode_depth")
            parse_deleted_option("uu_decode_depth", data_stream);

        else if (keyword == "iis_unicode_map")
        {
            std::string codemap;
            int code_page;

            if ( (data_stream >> codemap) &&
                (data_stream >> code_page))
            {
                tmpval = table_api.add_option("iis_unicode_map_file", codemap);
                tmpval = table_api.add_option("iis_unicode_code_page", code_page) && tmpval;
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

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new HttpInspect(c);
}

static const ConvertMap preprocessor_nhttpinspect =
{
    "http_inspect",
    ctor,
};

const ConvertMap* nhttpinspect_map = &preprocessor_nhttpinspect;
} // namespace preprocessors

