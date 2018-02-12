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
// kws_file.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <unordered_set>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace keywords
{
namespace
{

class File : public ConversionState
{
public:
    File(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;

private:
};
} // namespace

static std::unordered_set<std::string> string_keys = {
            "category", 
            "msg",
            "type",
            "ver",
            "group",
};

static std::unordered_set<std::string> int_keys = {
            "id",
            "rev",
};

static std::unordered_set<std::string> content_keys = {
            "content",
            "offset",
};

bool File::convert(std::istringstream& data_stream)
{
    std::string key_value_pair;
    bool retval = true;
    bool success = true;
    bool content_seen = false;
    std::vector<std::pair<std::string,std::string>> magics;

    table_api.open_table("file_magic");
    table_api.open_table(true);

    while(util::get_string(data_stream, key_value_pair, ";"))
    {
        std::istringstream arg_stream(key_value_pair);
        util::trim(key_value_pair);

        size_t pos = key_value_pair.find_first_of(':');
        if(pos == std::string::npos)
        {
            data_api.failed_conversion(arg_stream, key_value_pair);
            retval = false;
            continue;
        }

        std::string key = key_value_pair.substr(0, pos);
        std::string value = key_value_pair.substr(pos+1);

        if(key.empty() or value.empty())
        {
            table_api.add_comment("Empty field before or after ':' in: " + key_value_pair);
            data_api.failed_conversion(arg_stream, key_value_pair);
            retval = false;
            continue;
        }

        util::trim_quotes(value);

        if(string_keys.find(key) != string_keys.end())
        {
            if(key == "ver")
            {
                table_api.add_diff_option_comment("ver", "version");
                key = "version";
            }
            table_api.add_option(key, value);
        }
        else if(int_keys.find(key) != int_keys.end())
        {
            std::istringstream stream_value(value);
            success = parse_int_option(key, stream_value, false);
        }
        else if(content_keys.find(key) != content_keys.end())
        {
            // Save the content/offset pairs for later so they can be
            // added to a sub-table. Content must always come before offset
            // so start a new pair when content is seen.

            if(key == "content")
                content_seen = true;

            if(key == "offset" and not content_seen)
            {
                success = false;
                table_api.add_comment("Offset came before content field: " + key_value_pair);
            }
            else
            {
                if(key == "offset")
                    content_seen = false;   // Prevent two offsets in a row
                std::pair<std::string, std::string> pair(key, value);
                magics.push_back(pair);
            }

        }
        else
        {
            table_api.add_comment("Unknown rule field: " + key_value_pair);
            success = false;
        }

        if (!success)
        {
            data_api.failed_conversion(arg_stream, key_value_pair);
            retval = false;
        }
    }

    if(magics.size() > 0)
    {
        bool sub_table_open = false;

        table_api.open_table("magic");

        for(const std::pair<std::string, std::string>& key_value: magics)
        {
            if(key_value.first == "offset")
            {
                std::istringstream stream_value(key_value.second);
                success = parse_int_option(key_value.first, stream_value, false);
            }
            else if(key_value.first == "content")
            {
                // Create a new sub-table each time we see content.
                if(sub_table_open)
                    table_api.close_table();
                table_api.open_table();
                table_api.add_option(key_value.first, key_value.second);
                sub_table_open = true;
            }

            if (!success)
            {
                std::istringstream stream(key_value.first + ":" + key_value.second);
                data_api.failed_conversion(stream, stream.str());
                retval = false;
            }
        }

        if(sub_table_open)
            table_api.close_table();
        table_api.close_table();
    }

    table_api.close_table();
    table_api.close_table();

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new File(c); }

static const ConvertMap keyword_file =
{
    "file",
    ctor,
};

const ConvertMap* file_map = &keyword_file;
} // namespace keywords

