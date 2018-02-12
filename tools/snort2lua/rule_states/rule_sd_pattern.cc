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
// rule_sd_pattern.cc author Victor Roemer <viroemer@cisco.com>

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
class SDPattern : public ConversionState
{
public:
    SDPattern(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool SDPattern::convert(std::istringstream& stream)
{
    std::string count;
    std::string pattern;

    std::string args = util::get_rule_option_args(stream);
    std::istringstream arg_stream(args);

    if ( !util::get_string(arg_stream, count, ",")
      || !util::get_string(arg_stream, pattern, ","))
    {
        rule_api.bad_rule(stream, "sd_pattern missing arguments");
        return set_next_rule_state(stream);
    }

    rule_api.add_option("sd_pattern", "\"" + pattern + "\"");
    rule_api.add_suboption("threshold", count);

    return set_next_rule_state(stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new SDPattern(c);
}

static const std::string sd_pattern = "sd_pattern";
static const ConvertMap sd_pattern_api =
{
    sd_pattern,
    ctor,
};

const ConvertMap* sd_pattern_map = &sd_pattern_api;
} // namespace rules

