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
// pps_frag3_global.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
namespace
{
class Frag3Global : public ConversionState
{
public:
    Frag3Global(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool Frag3Global::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string keyword;

    table_api.open_table("stream_ip");

    // full options are comma separated
    while (util::get_string(data_stream, keyword, ","))
    {
        bool tmpval = true;

        // suboptions are space separated
        std::istringstream args_stream(keyword);
        args_stream >> keyword;

        if (keyword == "disabled")
            table_api.add_deleted_comment("disabled");

        else if (keyword == "max_frags")
            tmpval = parse_int_option("max_frags", args_stream, false);

        else if (keyword == "memcap")
            tmpval = parse_deleted_option("memcap", args_stream);

        else if (keyword == "prealloc_memcap")
            tmpval = parse_deleted_option("prealloc_memcap", args_stream);

        else if (keyword == "prealloc_frags")
            tmpval = parse_deleted_option("prealloc_frags", args_stream);

        else
            tmpval = false;

        if (!tmpval)
        {
            data_api.failed_conversion(data_stream, "keyword");
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
    return new Frag3Global(c);
}

static const ConvertMap preprocessor_frag3_global =
{
    "frag3_global",
    ctor,
};

const ConvertMap* frag3_global_map = &preprocessor_frag3_global;
} // namespace preprocessors

