/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 * Copyright (C) 2002-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// out_unified2.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "rule_states/rule_api.h"
#include "utils/snort2lua_util.h"

namespace output
{

namespace
{

template<const std::string* output_name>
class Unified2 : public ConversionState
{
public:
    Unified2( Converter* cv, LuaData* ld)
        :   ConversionState(cv, ld)
    { };
    virtual ~Unified2() {};

    virtual bool convert(std::istringstream& data_stream)
    {
        std::string args;
        bool retval = true;

        ld->open_table("unified2");

        if (!(*output_name).compare("unified2"))
            ld->add_diff_option_comment("output " + (*output_name), "unified2");

        while (std::getline(data_stream, args, ','))
        {
            bool tmpval = true;
            std::string keyword;

            std::istringstream arg_stream(args);
            arg_stream >> keyword;

            if (keyword.empty())
                continue;

            else if (!keyword.compare("nostamp"))
                tmpval = ld->add_option_to_table("nostamp", true);

            else if (!keyword.compare("mpls_event_types"))
                tmpval = ld->add_option_to_table("mpls_event_types", true);

            else if (!keyword.compare("vlan_event_types"))
                tmpval = ld->add_option_to_table("vlan_event_types", true);

            else if (!keyword.compare("filename"))
            {
                tmpval = parse_string_option("file", arg_stream);
                ld->add_diff_option_comment("filename", "file");
            }

            else if (!keyword.compare("limit"))
            {
                tmpval = parse_int_option("limit", arg_stream);
                tmpval = ld->add_option_to_table("units", "M") && tmpval;
            }

            else
                tmpval = false;

            if (retval)
                retval = tmpval;
        }

        return retval;
    }
};

template<const std::string* output_name>
static ConversionState* unified2_ctor(Converter* cv, LuaData* ld)
{
    ld->open_top_level_table("unified2"); // create table in case there are no arguments
    ld->close_table();
    return new Unified2<output_name>(cv, ld);
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
    unified2_ctor<&unified2>,
};

static const ConvertMap log_unified2_api =
{
    log_unified2,
    unified2_ctor<&log_unified2>,
};

static const ConvertMap alert_unified2_api =
{
    alert_unified2,
    unified2_ctor<&alert_unified2>,
};


const ConvertMap* unified2_map = &unified2_api;
const ConvertMap* log_unified2_map = &log_unified2_api;
const ConvertMap* alert_unified2_map = &alert_unified2_api;

} // output namespace

