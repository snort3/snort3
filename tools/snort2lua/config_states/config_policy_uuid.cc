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
// config_policy_uuid.cc author Steve Chew <stechew@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "data/dt_data.h"

namespace config
{
namespace
{
class PolicyUuid : public ConversionState
{
public:
    PolicyUuid(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool PolicyUuid::convert(std::istringstream& data_stream)
{
    bool rc = true;
    std::string policy_version;
    std::string policy_revision;

    // This could belong to either inspection or ips policy.
    // binder[].use.*_policy logic in snort will apply these correctly
    if (data_stream >> policy_version >> policy_revision)
    {
        // Had both a base policy version and revision. Use revision UUID.
        cv.get_table_api().open_table("inspection");
        cv.get_table_api().add_option("uuid", policy_revision);
        cv.get_table_api().close_table();
        cv.get_table_api().open_table("ips");
        cv.get_table_api().add_option("uuid", policy_revision);
        cv.get_table_api().close_table();
    }
    else if (!policy_version.empty())
    {
        // Had only a base policy version.
        cv.get_table_api().open_table("inspection");
        cv.get_table_api().add_option("uuid", policy_version);
        cv.get_table_api().close_table();
        cv.get_table_api().open_table("ips");
        cv.get_table_api().add_option("uuid", policy_version);
        cv.get_table_api().close_table();
    }
    else
    {
        data_api.failed_conversion(data_stream, "config policy_version: failed to find UUID.");
        rc = false;
    }

    return rc;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{ return new PolicyUuid(c); }

static const ConvertMap policy_uuid_api =
{
    "policy_version",
    ctor,
};

const ConvertMap* policy_uuid_map = &policy_uuid_api;
} // namespace config

