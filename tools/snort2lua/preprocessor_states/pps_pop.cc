//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// pps_pop.cc author Bhagya Bantwal <bbantwal@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace
{
class Pop : public ConversionState
{
public:
    Pop(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;

};
} // namespace

bool Pop::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    bool ports_set = false;
    auto& bind = cv.make_binder();

    bind.set_when_proto("tcp");
    bind.set_use_type("pop");

    table_api.open_table("pop");


    // parse the file configuration
    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword == "disabled")
        {
            table_api.add_deleted_comment("disabled");
        }

        else if (keyword == "memcap")
        {
            table_api.add_deleted_comment("memcap");
            data_stream >> keyword;
        }

        else if (keyword == "max_mime_mem")
        {
            table_api.add_deleted_comment("max_mime_mem");
            data_stream >> keyword;
        }

        else if (keyword == "b64_decode_depth")
        {
            tmpval = parse_int_option_reverse_m10("b64_decode_depth", data_stream);
        }

        else if (keyword == "qp_decode_depth")
        {
            tmpval = parse_int_option_reverse_m10("qp_decode_depth", data_stream);
        }

        else if (keyword == "bitenc_decode_depth")
        {
            tmpval = parse_int_option_reverse_m10("bitenc_decode_depth", data_stream);
        }

        else if (keyword == "uu_decode_depth")
        {
            tmpval = parse_int_option_reverse_m10("uu_decode_depth", data_stream);
        }

        else if (keyword == "ports")
        {
            table_api.add_diff_option_comment("ports", "bindings");

            if ((data_stream >> keyword) && keyword == "{")
            {
                while (data_stream >> keyword && keyword != "}")
                {
                    ports_set = true;
                    bind.add_when_port(keyword);
                }
            }
            else
            {
                data_api.failed_conversion(data_stream, "ports <bracketed_port_list>");
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

    if (!ports_set)
        bind.add_when_port("110");

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new Pop(c);
}

static const ConvertMap preprocessor_pop =
{
    "pop",
    ctor,
};

const ConvertMap* pop_map = &preprocessor_pop;
}

