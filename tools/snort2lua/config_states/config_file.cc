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
// config_file.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "data/dt_table_api.h"

namespace config
{
namespace
{
class File : public ConversionState
{
public:
    File(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool File::convert(std::istringstream& data_stream)
{
    std::string args;
    bool retval = true;

    table_api.open_table("file_id");
    while (util::get_string(data_stream, args, ","))
    {
        std::istringstream arg_stream(args);
        std::string keyword = std::string();
        bool tmpval = true;

        if (!(arg_stream >> keyword))
            tmpval = false;

        // vvvvvvvv -- UNSUPPORTED OPTIONS.  these options were added after 2.9.6
        else if (keyword == "file_capture_memcap")
            table_api.add_unsupported_comment("file_capture_memcap");

        else if (keyword == "file_capture_max")
            table_api.add_unsupported_comment("file_capture_max");

        else if (keyword == "file_capture_min")
            table_api.add_unsupported_comment("file_capture_min");

        else if (keyword == "file_capture_block_size")
            table_api.add_unsupported_comment("file_capture_block_size");
        // ^^^^^^^^^ -- UNSUPPORTED OPTIONS.  these options were added after 2.9.6

        else if (keyword == "show_data_depth")
            tmpval = parse_int_option("show_data_depth", arg_stream, false);

        else if (keyword == "type_id")
        {
            table_api.add_diff_option_comment("config file: type_id", "enable_type");
            table_api.add_option("enable_type", true);
        }
        else if (keyword == "signature")
        {
            table_api.add_diff_option_comment("config file: signature", "enable_signature");
            table_api.add_option("enable_signature", true);
        }
        else if (keyword == "file_type_depth")
        {
            table_api.add_diff_option_comment("config file: file_type_depth", "type_depth");
            tmpval = parse_int_option("type_depth", arg_stream, false);
        }
        else if (keyword == "file_signature_depth")
        {
            table_api.add_diff_option_comment("config file: file_signature_depth",
                "signature_depth");
            tmpval = parse_int_option("signature_depth", arg_stream, false);
        }
        else if (keyword == "file_block_timeout")
        {
            table_api.add_diff_option_comment("config file: file_block_timeout", "block_timeout");
            tmpval = parse_int_option("block_timeout", arg_stream, false);
        }
        else if (keyword == "file_lookup_timeout")
        {
            table_api.add_diff_option_comment("config file: file_lookup_timeout",
                "lookup_timeout");
            tmpval = parse_int_option("lookup_timeout", arg_stream, false);
        }
        else
            tmpval = false;

        if (retval && !tmpval)
            retval = false;
    }

    // Always add the file_rules option to reference the file magic rules.
    table_api.add_option("file_rules", "$file_magic");

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new File(c);
}

static const ConvertMap file_api =
{
    "file",
    ctor,
};

const ConvertMap* file_map = &file_api;
} // namespace config

