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
// config_file.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "util/converter.h"
#include "util/util.h"

namespace config
{

namespace {

class File : public ConversionState
{
public:
    File(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~File() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool File::convert(std::istringstream& data_stream)
{
    std::string args;
    bool retval = true;

    ld->open_table("file_id");
    while(util::get_string(data_stream, args, ","))
    {
        std::istringstream arg_stream(args);
        std::string keyword = std::string();
        bool tmpval = true;

        if (!(arg_stream >> keyword))
            tmpval = false;

        // vvvvvvvv -- UNSUPPORTED OPTIONS.  these options were added after 2.9.6
        else if (!keyword.compare("file_capture_memcap"))
            ld->add_unsupported_comment("file_capture_memcap");

        else if (!keyword.compare("file_capture_max"))
            ld->add_unsupported_comment("file_capture_max");

        else if (!keyword.compare("file_capture_min"))
            ld->add_unsupported_comment("file_capture_min");

        else if (!keyword.compare("file_capture_block_size"))
            ld->add_unsupported_comment("file_capture_block_size");
        // ^^^^^^^^^ -- UNSUPPORTED OPTIONS.  these options were added after 2.9.6

        else if (!keyword.compare("show_data_depth"))
            tmpval = parse_int_option("show_data_depth", arg_stream);

        else if (!keyword.compare("type_id"))
        {
            ld->add_diff_option_comment("config file: type_id", "enable_type");
            ld->add_option_to_table("enable_type", true);
        }

        else if (!keyword.compare("signature"))
        {
            ld->add_diff_option_comment("config file: signature", "enable_signature");
            ld->add_option_to_table("enable_signature", true);
        }

        else if (!keyword.compare("file_type_depth"))
        {
            ld->add_diff_option_comment("config file: file_type_depth", "type_depth");
            tmpval = parse_int_option("type_depth", arg_stream);
        }

        else if (!keyword.compare("file_signature_depth"))
        {
            ld->add_diff_option_comment("config file: file_signature_depth", "signature_depth");
            tmpval = parse_int_option("signature_depth", arg_stream);
        }

        else if (!keyword.compare("file_block_timeout"))
        {
            ld->add_diff_option_comment("config file: file_block_timeout", "block_timeout");
            tmpval = parse_int_option("block_timeout", arg_stream);
        }

        else if (!keyword.compare("file_lookup_timeout"))
        {
            ld->add_diff_option_comment("config file: file_lookup_timeout", "lookup_timeout");
            tmpval = parse_int_option("lookup_timeout", arg_stream);
        }

        else
            tmpval = false;

        if (retval && !tmpval)
            retval = false;
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new File(cv, ld);
}

static const ConvertMap file_api =
{
    "file",
    ctor,
};

const ConvertMap* file_map = &file_api;

} // namespace config
