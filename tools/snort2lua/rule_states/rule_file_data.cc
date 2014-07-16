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
// rule_file_data.cc author Josh Rosenbaum <jorosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "rule_states/rule_api.h"
#include "utils/snort2lua_util.h"

namespace rules
{

namespace {


class FileData : public ConversionState
{
public:
    FileData(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~FileData() {};
    virtual bool convert(std::istringstream& data);
};

} // namespace

bool FileData::convert(std::istringstream& data_stream)
{
    std::string args;
    std::string tmp;
    int pos = data_stream.tellg();
    bool retval = true;

    retval = ld->add_rule_option("file_data");
    args = util::get_rule_option_args(data_stream);

    // if there are no arguments, the option had a colon before a semicolon.
    // we are therefore done with this rule.
    if (!args.empty())
    {
        // a colon will have been parsed when retrieving the keyword.
        // Therefore, if a colon is present, we are in the next rule option.
        if (args.find(":") != std::string::npos)
        {
            data_stream.seekg(pos);
        }
        else
        {
            // since we still can't be sure if we passed the file_data buffer,
            // check the next option and ensure it matches 'mime'
            std::istringstream(args) >> tmp;

            if (!tmp.compare("mime"))
                ld->add_comment_to_rule("file_data's option 'mime' has been deleted");
            else
                data_stream.seekg(pos);
        }
    }
    return set_next_rule_state(data_stream) && retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* file_data_ctor(Converter* cv, LuaData* ld)
{
    return new FileData(cv, ld);
}

static const ConvertMap rule_file_data =
{
    "file_data",
    file_data_ctor,
};

const ConvertMap* file_data_map = &rule_file_data;

} // namespace rules
