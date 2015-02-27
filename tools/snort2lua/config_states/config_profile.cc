//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// config_profile.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
template<const std::string* table_name>
class Profilers : public ConversionState
{
public:
    Profilers(Converter& c) : ConversionState(c) { }
    virtual ~Profilers() { }
    virtual bool convert(std::istringstream& data_stream);
};
} // namespace

template<const std::string* table_name>
bool Profilers<table_name>::convert(std::istringstream& data_stream)
{
    std::string args;
    bool retval = true;

    table_api.open_table("profile");
    table_api.open_table(*table_name);

    while (util::get_string(data_stream, args, ","))
    {
        bool tmpval = true;
        std::istringstream arg_stream (args);
        std::string keyword;

        if (!(arg_stream >> keyword))
            tmpval = false;

        else if (!keyword.compare("filename"))
        {
            table_api.add_deleted_comment("profile_*: filename ...");
        }
        else if (!keyword.compare("print"))
        {
            table_api.add_diff_option_comment("print", "count");

            std::string tmp_string;
            if (!(arg_stream >> tmp_string))
                tmpval = false;

            else if (!tmp_string.compare("all"))
                tmpval = table_api.add_option("count", -1);

            else if (isdigit(tmp_string[0]) ||
                (tmp_string[0] == '-') ||
                (tmp_string[0] == '+'))
                tmpval = table_api.add_option("count", std::stoi(tmp_string));

            else
                tmpval = false;
        }
        else if (!keyword.compare("sort"))
        {
            std::string val;

            if (!(arg_stream >> val))
                tmpval = false;

            else if (!val.compare("avg_ticks_per_nomatch"))
            {
                table_api.add_diff_option_comment("sort avg_ticks_per_nomatch",
                    "sort = avg_ticks_per_no_match");
                tmpval = table_api.add_option("sort", "avg_ticks_per_no_match");
            }
            else
                tmpval = table_api.add_option("sort", val);
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

    table_api.close_table();
    return retval;
}

template<const std::string* table_name>
static ConversionState* ctor(Converter& c)
{
    c.get_table_api().open_table("profile");
    c.get_table_api().open_table(*table_name);
    c.get_table_api().close_table();
    c.get_table_api().close_table();
    return new Profilers<table_name>(c);
}

/**************************
 *******  A P I ***********
 **************************/

static const std::string rules = "rules";
static const std::string modules = "modules";

static const ConvertMap profile_rules_api =
{
    "profile_rules",
    ctor<& rules>,
};

static const ConvertMap profile_preprocs_api =
{
    "profile_preprocs",
    ctor<& modules>,
};

const ConvertMap* profile_rules_map = &profile_rules_api;
const ConvertMap* profile_preprocs_map = &profile_preprocs_api;
} // namespace config

