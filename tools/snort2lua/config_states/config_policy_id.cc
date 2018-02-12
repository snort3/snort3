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
// config_policy_id.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "data/dt_data.h"

namespace config
{
namespace
{
class PolicyId : public ConversionState
{
public:
    PolicyId(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool PolicyId::convert(std::istringstream& data_stream)
{
    bool rc = true;
    int policy_id;

    if (data_stream >> policy_id)
    {
        cv.get_table_api().open_table("ips");
        cv.get_table_api().add_option("id", policy_id);
        cv.get_table_api().close_table();

        cv.get_table_api().open_table("network");
        cv.get_table_api().add_option("id", policy_id);
        cv.get_table_api().close_table();
    }
    else
    {
        data_api.failed_conversion(data_stream, "<int>");
        rc = false;
    }

    if (data_stream >> policy_id)
    {
        data_api.failed_conversion(data_stream, std::to_string(policy_id));
        rc = false;
    }

    return rc;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new PolicyId(c); }

static const ConvertMap policy_id_api =
{
    "policy_id",
    ctor,
};

const ConvertMap* policy_id_map = &policy_id_api;
} // namespace config

