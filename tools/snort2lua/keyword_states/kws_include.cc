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
// kws_include.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>
#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"
#include "helpers/parse_cmd_line.h"
#include "data/data_types/dt_comment.h"
#include "keywords_api.h"

namespace keywords
{
namespace
{
class Include : public ConversionState
{
public:
    Include(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool Include::convert(std::istringstream& data_stream)
{
    std::string file = util::get_remain_data(data_stream);

    if (!file.empty())
    {
        // if not parsing, assume its a regular rule file.
        if (cv.get_parse_includes())
        {
            std::string full_file = data_api.expand_vars(file);
            std::string tmp = full_file; // for the error message

            //check if the file exists using what was provided
            //if not use the conf_dir with the file
            if (!util::file_exists(full_file))
                full_file = parser::get_conf_dir() + full_file;

            // make sure its a regular file (not a directory)
            if (util::is_regular_file(full_file))
            {
                return !cv.parse_include_file(full_file);
            }
            else
            { //cant find it .. log error
                std::string error_string = "Can't find file " + file + ".  "
                "  Searched locations: [" + tmp + "],  [" + full_file + "]";

                data_api.failed_conversion(data_stream, error_string);
            }
        }
    }
    else
    {
        data_api.failed_conversion(data_stream, "include requires a 'filename' argument");
    }

    return false;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new Include(c); }

static const ConvertMap keyword_include =
{
    "include",
    ctor,
};

const ConvertMap* include_map = &keyword_include;
}  // namespace keywords
