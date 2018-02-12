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
// config_mpls_payload_type.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class MplsPayloadType : public ConversionState
{
public:
    MplsPayloadType(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool MplsPayloadType::convert(std::istringstream& data_stream)
{
    std::string type;
    bool retval = true;

    if (!(data_stream >> type))
        return false;

    table_api.open_table("mpls");

    if (type == "ethernet")
    {
        table_api.add_diff_option_comment("config mpls_payload_type: ethernet",
            "mpls_payload_type = eth");
        retval = table_api.add_option("mpls_payload_type", "eth");
    }
    else if (type == "ipv4")
    {
        table_api.add_diff_option_comment("config mpls_payload_type: ipv4",
            "mpls_payload_type = ip4");
        retval = table_api.add_option("mpls_payload_type", "ip4");
    }
    else if (type == "ipv6")
    {
        table_api.add_diff_option_comment("config mpls_payload_type: ipv6",
            "mpls_payload_type = ip6");
        retval = table_api.add_option("mpls_payload_type", "ip6");
    }
    else
        return false;

    data_stream.setstate(std::ios::eofbit); // if additional options available, stop parsing.
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new MplsPayloadType(c);
}

static const ConvertMap mpls_payload_type_api =
{
    "mpls_payload_type",
    ctor,
};

const ConvertMap* mpls_payload_type_map = &mpls_payload_type_api;
} // namespace config

