//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// rule_dnp3_obj.cc author Maya Dagon <mdagon@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
namespace
{
class DNP3Obj : public ConversionState
{
public:
    DNP3Obj(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool DNP3Obj::convert(std::istringstream& data)
{
    std::string val = util::get_rule_option_args(data);
    std::string group = "group ";
    std::string var = " var ";

    /* convert from dnp3_obj: xxx,xxx to
     * dnp3_obj: group xxx, var xxxx
     */
    val.insert(0, group);
    size_t start_pos = val.find(',');
    if (start_pos == std::string::npos)
        rule_api.bad_rule(data, "dnp3_obj:expecting 2 args separated by comma");
    else
        val.insert(start_pos+1, var);

    rule_api.add_option("dnp3_obj", val);
    return set_next_rule_state(data);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& cv)
{
    return new DNP3Obj(cv);
}

static const std::string dnp3_obj = "dnp3_obj";
static const ConvertMap dnp3_obj_api =
{
    dnp3_obj,
    ctor,
};

const ConvertMap* dnp3_obj_map = &dnp3_obj_api;
} // namespace rules

