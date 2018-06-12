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
// rule_file_type.cc author Victor Roemer <viroemer@cisco.com>

#include <algorithm>
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
class FileType : public ConversionState
{
public:
    FileType(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream&) override;
};
} // namespace

bool FileType::convert(std::istringstream& stream)
{
    std::string types = util::get_rule_option_args(stream);
    if (types.empty())
    {
        rule_api.bad_rule(stream, "file_type: expecting at least one argument");
    }

    std::replace(types.begin(), types.end(), '|', ' ');
    rule_api.add_option("file_type", "\"" + types + "\"");

    return set_next_rule_state(stream);
}

static ConversionState* ctor(Converter& c)
{ return new FileType(c); }

static const std::string file_type = "file_type";
static const ConvertMap file_type_api =
{
    file_type,
    ctor,
};

const ConvertMap* file_type_map = &file_type_api;
} // namespace rules

