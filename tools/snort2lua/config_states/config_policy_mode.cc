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
// config_policy_mode.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class PolicyMode : public ConversionState
{
public:
    PolicyMode(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool PolicyMode::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string mode;

    if ( data_stream >> mode)
    {
        cv.get_table_api().open_table("ips");

        if ( mode == "tap")
        {
            cv.get_table_api().add_option("mode", "tap");
        }
        else if ( mode == "inline" )
        {
            cv.get_table_api().add_option("mode", "inline");
        }
        else if ( mode == "inline_test" )
        {
            cv.get_table_api().add_diff_option_comment("inline_test", "inline-test");
            cv.get_table_api().add_option("mode", "inline-test");
        }
        else
        {
            retval = false;
            data_api.failed_conversion(data_stream, mode);
        }

        cv.get_table_api().close_table();
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new PolicyMode(c); }

static const ConvertMap policy_mode_api =
{
    "policy_mode",
    ctor,
};

const ConvertMap* policy_mode_map = &policy_mode_api;
} // namespace config

