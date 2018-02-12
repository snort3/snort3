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
// config_ipv6_frag.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class Ipv6Frag : public ConversionState
{
public:
    Ipv6Frag(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;

private:
    void add_deleted_option(const std::string& opt);
};
} // namespace

void Ipv6Frag::add_deleted_option(const std::string& dlt_opt)
{
    // see comment in Ipv6Frag::convert
    if (!DataApi::is_quiet_mode())
        table_api.add_deleted_comment("config ipv6_frag: " + dlt_opt);
}

bool Ipv6Frag::convert(std::istringstream& data_stream)
{
    bool retval = true;
    std::string arg;

    // I'm checking here because I do not want to create this
    // table in quiet mode
    if (!DataApi::is_quiet_mode())
        table_api.open_table("deleted_snort_config_options");

    while (util::get_string(data_stream, arg, ","))
    {
        bool tmpval = true;
        std::string keyword;
        std::istringstream arg_stream(arg);

        if (!(arg_stream >> keyword))
            tmpval = false;

        else if (keyword == "max_frag_sessions")
            add_deleted_option("max_frag_sessions");

        else if (keyword == "bsd_icmp_frag_alert")
            add_deleted_option("config ipv6_frag: bsd_icmp_frag_alert");

        else if (keyword == "bad_ipv6_frag_alert")
            add_deleted_option("bad_ipv6_frag_alert");

        else if (keyword == "drop_bad_ipv6_frag")
            add_deleted_option("drop_bad_ipv6_frag");

        else if (keyword == "frag_timeout")
        {
            table_api.open_top_level_table("ip_stream");
            tmpval = parse_int_option("session_timeout", arg_stream, false);
            table_api.close_table();
        }
        else
        {
            tmpval = false;
        }

        if (retval && !tmpval)
            retval = false;
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new Ipv6Frag(c);
}

static const ConvertMap ipv6_frag_api =
{
    "ipv6_frag",
    ctor,
};

const ConvertMap* ipv6_frag_map = &ipv6_frag_api;
} // namespace config

