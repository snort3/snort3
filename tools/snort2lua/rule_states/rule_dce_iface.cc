//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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
// rule_dce_iface.cc author Maya Dagon <mdagon@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
namespace
{
class DCEIface : public ConversionState
{
public:
    DCEIface(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data) override;
};
} // namespace

bool DCEIface::convert(std::istringstream& data)
{
    std::string val = util::get_rule_option_args(data);

    /* convert from dce_iface: <uuid> [, <operator><version>] [, any_frag] to
     * dce_iface: uuid <uuid> [, version <operator><version>] [, any_frag]
     */
    val.insert(0, "uuid ");
    size_t start_pos = val.find(',');
    while (start_pos != std::string::npos)
    {
        size_t next_pos = val.find(',', start_pos+1);
        std::string substring;

        if (next_pos != std::string::npos)
            substring = val.substr(start_pos+1, next_pos-start_pos);
        else
            substring = val.substr(start_pos+1);

        if (substring.find("any_frag") == std::string::npos)
        {
            val.insert(start_pos+1, "version ");
            break;
        }

        start_pos = next_pos;
    }

    rule_api.add_option("dce_iface", val);
    return set_next_rule_state(data);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& cv)
{
    return new DCEIface(cv);
}

static const std::string dce_iface = "dce_iface";
static const ConvertMap dce_iface_api =
{
    dce_iface,
    ctor,
};

const ConvertMap* dce_iface_map = &dce_iface_api;
} // namespace rules

