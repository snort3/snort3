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
// out_unified2.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace output
{
namespace
{
template<const std::string* output_name>
class Unified2 : public ConversionState
{
public:
    Unified2(Converter& c) : ConversionState(c) { }

    bool convert(std::istringstream& data_stream) override
    {
        std::string args;
        bool retval = true;

        table_api.open_table("unified2");

        if ((*output_name) == "unified2")
            table_api.add_diff_option_comment("output " + (*output_name), "unified2");

        while (std::getline(data_stream, args, ','))
        {
            bool tmpval = true;
            std::string keyword;

            std::istringstream arg_stream(args);
            arg_stream >> keyword;

            if (keyword.empty())
                continue;

            else if (keyword == "nostamp")
                tmpval = table_api.add_option("nostamp", true);

            else if (keyword == "mpls_event_types")
                table_api.add_deleted_comment("mpls_event_types");

            else if (keyword == "vlan_event_types")
                tmpval = table_api.add_deleted_comment("vlan_event_types");

            else if (keyword == "filename")
                table_api.add_deleted_comment("filename");

            else if (keyword == "limit")
                tmpval = parse_int_option("limit", arg_stream, false);

            else
                tmpval = false;

            if (retval)
                retval = tmpval;
        }

        return retval;
    }
};

template<const std::string* output_name>
static ConversionState* unified2_ctor(Converter& c)
{
    c.get_table_api().open_top_level_table("unified2"); // create table in case there are no
                                                        // arguments
    c.get_table_api().close_table();
    return new Unified2<output_name>(c);
}
} // namespace

/**************************
 *******  A P I ***********
 **************************/

static const std::string unified2 = "unified2";
static const std::string log_unified2 = "log_unified2";
static const std::string alert_unified2 = "alert_unified2";

static const ConvertMap unified2_api =
{
    unified2,
    unified2_ctor<& unified2>,
};

static const ConvertMap log_unified2_api =
{
    log_unified2,
    unified2_ctor<& log_unified2>,
};

static const ConvertMap alert_unified2_api =
{
    alert_unified2,
    unified2_ctor<& alert_unified2>,
};

const ConvertMap* unified2_map = &unified2_api;
const ConvertMap* log_unified2_map = &log_unified2_api;
const ConvertMap* alert_unified2_map = &alert_unified2_api;
} // output namespace

