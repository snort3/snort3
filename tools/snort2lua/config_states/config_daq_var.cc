//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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
// config_daq_var.cc author Carter Waxman <cwaxman@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class DaqVar : public ConversionState
{
public:
    DaqVar(Converter& c) : ConversionState(c) { }

    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool DaqVar::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string tmp, var;

    while ( data_stream >> tmp )
        var += tmp;

    if ( !var.empty() )
    {
        table_api.open_top_level_table("daq");
        table_api.open_table("modules");
        table_api.open_table("");
        table_api.open_table("variables");
        table_api.add_option(var);
        table_api.close_table();
        table_api.add_diff_option_comment("config daq_var:", "variables");
        table_api.close_table();
        table_api.close_table();
        table_api.close_table();
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new DaqVar(c); }

static const ConvertMap daq_var_api =
{
    "daq_var",
    ctor,
};

const ConvertMap* daq_var_map = &daq_var_api;

} // namespace config

