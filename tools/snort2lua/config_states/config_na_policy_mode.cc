//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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
// config_na_policy_mode.cc author Carter Waxman <cwaxman@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class NaPolicyMode : public ConversionState
{
public:
    NaPolicyMode(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool NaPolicyMode::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string mode;

    if ( data_stream >> mode)
    {
        if ( mode == "tap" || mode == "inline_test" )
        {
            table_api.open_top_level_table("inspection");
            table_api.add_option("mode", "inline-test");
            table_api.add_diff_option_comment("na_policy_mode", "mode");
            table_api.close_table();
        }
        else if ( mode == "inline" )
        {
            table_api.open_top_level_table("inspection");
            table_api.add_option("mode", "inline");
            table_api.add_diff_option_comment("na_policy_mode", "mode");
            table_api.close_table();
        }
        else
        {
            retval = false;
            data_api.failed_conversion(data_stream, mode);
        }
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new NaPolicyMode(c); }

static const ConvertMap na_policy_mode_api =
{
    "na_policy_mode",
    ctor,
};

const ConvertMap* na_policy_mode_map = &na_policy_mode_api;

} // namespace config

