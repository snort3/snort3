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
// pps_dns.cc author Bhagya Bantwal <bbantwal@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/s2l_util.h"
#include "helpers/util_binder.h"

namespace preprocessors
{
namespace
{
class Dns : public ConversionState
{
public:
    Dns(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;

};
} // namespace

bool Dns::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    bool ports_set = false;
    auto& bind = cv.make_binder();

    bind.set_when_proto("tcp");
    bind.set_use_type("dns");

    table_api.open_table("dns");


    // parse the file configuration
    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (keyword == "enable_obsolete_types")
            table_api.add_deleted_comment("enable_obsolete_types");

        else if (keyword == "enable_experimental_types")
            table_api.add_deleted_comment("enable_experimental_types");

        else if (keyword == "enable_rdata_overflow")
            table_api.add_deleted_comment("enable_rdata_overflow");

        else if (keyword == "ports")
        {
            table_api.add_diff_option_comment("ports", "bindings");

            if ((data_stream >> keyword) && keyword == "{")
            {
                while (data_stream >> keyword && keyword != "}")
                {
                    ports_set = true;
                    bind.add_when_port(keyword);
                }
            }
            else
            {
                data_api.failed_conversion(data_stream, "ports <bracketed_port_list>");
                retval = false;
            }
        }

        else
        {
            tmpval = false;
        }

        if (!tmpval)
        {
            data_api.failed_conversion(data_stream, keyword);
            retval = false;
        }
    }

    if (!ports_set)
        bind.add_when_port("53");

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new Dns(c);
}

static const ConvertMap preprocessor_dns =
{
    "dns",
    ctor,
};

const ConvertMap* dns_map = &preprocessor_dns;
}

