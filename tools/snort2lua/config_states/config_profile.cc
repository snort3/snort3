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
    bool convert(std::istringstream& data_stream) override;

    template<typename T>
    bool add_or_append(const std::string& opt_name, T val)
    {
        if ( table_api.option_exists(opt_name) )
        {
            table_api.append_option(opt_name, val);
            return true;
        }

        table_api.add_option(opt_name, val);
        return false;
    }

    template<typename T>
    bool append_if_exists(const std::string& opt_name, T val)
    {
        if ( table_api.option_exists(opt_name) )
        {
            table_api.add_option(opt_name, val);
            return true;
        }

        return false;
    }
};
} // namespace

template<const std::string* table_name>
bool Profilers<table_name>::convert(std::istringstream& data_stream)
{
    std::string args;
    bool retval = true;

    table_api.open_table("profiler");
    table_api.open_table(*table_name);

    while (util::get_string(data_stream, args, ","))
    {
        bool tmpval = true;
        std::istringstream arg_stream (args);
        std::string keyword;

        if (!(arg_stream >> keyword))
            tmpval = false;

        else if (keyword == "filename")
            table_api.add_deleted_comment("profile_*: filename ...");

        else if (keyword == "print")
        {
            table_api.add_diff_option_comment("print", "count");

            std::string tmp_string;
            if (!(arg_stream >> tmp_string))
                tmpval = false;

            else if (tmp_string == "all")
            {
                // count = 0 is the default, so we don't need
                // to specify unless we're overriding a previously
                // defined value
                if ( append_if_exists("count", 0) )
                    // same with show = true
                    append_if_exists("show", true);
            }

            else if (isdigit(tmp_string[0]) ||
                (tmp_string[0] == '-') ||
                (tmp_string[0] == '+'))
            {
                auto count = std::stoi(tmp_string);

                if ( count > 0 )
                {
                    if ( add_or_append("count", count) )
                        if ( table_api.option_exists("show") )
                            table_api.append_option("show", true);
                }

                else if ( count < 0 )
                {
                    if ( append_if_exists("count", 0) )
                        append_if_exists("show", true);
                }

                else
                    add_or_append("show", false);
            }

            else
                tmpval = false;
        }
        else if (keyword == "sort")
        {
            std::string val;

            if (!(arg_stream >> val))
                tmpval = false;

            else if (val == "avg_ticks")
            {
                table_api.add_diff_option_comment("sort avg_ticks", "sort = avg_check");
                add_or_append("sort", "avg_check");
            }
            else if (val == "total_ticks")
            {
                table_api.add_diff_option_comment("sort total_ticks", "sort = total_time");
                add_or_append("sort", "total_time");
            }
            else if (val == "avg_ticks_per_match")
            {
                table_api.add_diff_option_comment("sort avg_ticks_per_match",
                    "sort = avg_match");
                add_or_append("sort", "avg_match");
            }
            else if (val == "avg_ticks_per_nomatch")
            {
                table_api.add_diff_option_comment("sort avg_ticks_per_nomatch",
                    "sort = avg_no_match");
                add_or_append("sort", "avg_no_match");
            }
            else if (val == "nomatches")
            {
                table_api.add_diff_option_comment("sort nomatches",
                    "sort = no_matches");
                add_or_append("sort", "no_matches");
            }
            else
                add_or_append("sort", val);
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
    c.get_table_api().open_table("profiler");
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

