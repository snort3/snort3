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
// rule_file_data.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
namespace
{
class FileData : public ConversionState
{
public:
    FileData(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool FileData::convert(std::istringstream& data_stream)
{
    std::string args;
    std::string tmp;
    std::streamoff pos = data_stream.tellg();

    rule_api.add_option("file_data");
    args = util::get_rule_option_args(data_stream);

    // if there are no arguments, the option had a colon before a semicolon.
    // we are therefore done with this rule.
    if (!args.empty())
    {
        // a colon will have been parsed when retrieving the keyword.
        // Therefore, if a colon is present, we are in the next rule option.
        if (args.find(':') != std::string::npos)
        {
            data_stream.clear();
            data_stream.seekg(pos);
        }
        else
        {
            // since we still can't be sure if we passed the file_data buffer,
            // check the next option and ensure it matches 'mime'
            std::istringstream(args) >> tmp;

            if (tmp == "mime")
            {
                rule_api.add_comment("file_data's 'mime' option has been deleted");
            }
            else
            {
                data_stream.clear();
                data_stream.seekg(pos);
            }
        }
    }
    return set_next_rule_state(data_stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* file_data_ctor(Converter& c)
{
    return new FileData(c);
}

static const ConvertMap rule_file_data =
{
    "file_data",
    file_data_ctor,
};

const ConvertMap* file_data_map = &rule_file_data;
} // namespace rules

