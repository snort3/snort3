/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// kws_include.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/s2l_util.h"
#include "utils/parse_cmd_line.h"

namespace keywords
{

namespace {

class Include : public ConversionState
{
public:
    Include(Converter& c) : ConversionState(c) {};
    virtual ~Include() {};
    virtual bool convert(std::istringstream& data);
};

} // namespace


bool Include::convert(std::istringstream& data_stream)
{
    std::string file = std::string();
    std::string tmp;

    while (data_stream >> tmp)
        file += tmp;

    if(!file.empty())
    {
        // if not parsing, assume its a regular rule file.


        if (cv.should_convert_includes())
        {
            std::string full_file = data_api.expand_vars(file);

            if (!util::file_exists(full_file))
                full_file = parser::get_conf_dir() + full_file;


            // if we still can't find this file, add it as a snort file
            if (util::file_exists(full_file))
            {
                cv.parse_include_file(full_file);
                return true;
            }
        }
    }

    rule_api.add_hdr_data("include " + file);
    data_api.failed_conversion(data_stream, "file: " + file);
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
