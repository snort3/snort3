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
// config_detection.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace config
{
namespace
{
class Detection : public ConversionState
{
public:
    Detection(Converter& c) : ConversionState(c) { }
    bool convert(std::istringstream& data_stream) override;
};
} // namespace

bool Detection::convert(std::istringstream& data_stream)
{
    bool retval = true;
    bool split_set = false;
    std::string args;

    table_api.open_table("search_engine");
    table_api.add_comment("This table was previously 'config detection: ...");

    while (util::get_string(data_stream, args, ", "))
    {
        bool tmpval = true;
        std::string keyword;
        std::istringstream arg_stream(args);

        if (!(arg_stream >> keyword)) // impossible to fail. get_string() will return false first.
            tmpval = false;

        else if (keyword == "no_stream_inserts")
        {
            table_api.add_diff_option_comment("no_stream_inserts", "detect_raw_tcp");
            tmpval = table_api.add_option("detect_raw_tcp", false);
        }

        else if (keyword == "debug")
            tmpval = table_api.add_option("debug", true);

        else if (keyword == "search-optimize")
        {
            table_api.add_diff_option_comment("search-optimize", "search_optimize");
            tmpval = table_api.add_option("search_optimize", true);
        }
        else if (keyword == "split-any-any")
        {
            table_api.add_diff_option_comment("split-any-any", "split_any_any");
            tmpval = table_api.add_option("split_any_any", true);
            split_set = true;
        }
        else if (keyword == "bleedover-warnings-enabled")
        {
            table_api.add_diff_option_comment("bleedover-warnings-enabled",
                "bleedover_warnings_enabled");
            tmpval = table_api.add_option("bleedover_warnings_enabled", true);
        }
        else if (keyword == "enable-single-rule-group")
        {
            table_api.add_diff_option_comment("enable-single-rule-group",
                "enable_single_rule_group");
            tmpval = table_api.add_option("enable_single_rule_group", true);
        }
        else if (keyword == "debug-print-nocontent-rule-tests")
        {
            table_api.add_diff_option_comment("debug-print-nocontent-rule-tests",
                "debug_print_nocontent_rule_tests");
            tmpval = table_api.add_option("debug_print_nocontent_rule_tests", true);
        }
        else if (keyword == "debug-print-rule-groups-compiled")
        {
            table_api.add_diff_option_comment("debug-print-rule-groups-compiled",
                "debug_print_rule_groups_compiled");
            tmpval = table_api.add_option("debug_print_rule_groups_compiled", true);
        }
        else if (keyword == "debug-print-rule-groups-uncompiled")
        {
            table_api.add_diff_option_comment("debug-print-rule-groups-uncompiled",
                "debug_print_rule_groups_uncompiled");
            tmpval = table_api.add_option("debug_print_rule_groups_uncompiled", true);
        }
        else if (keyword == "debug-print-rule-group-build-details")
        {
            table_api.add_diff_option_comment("debug-print-rule-group-build-details",
                "debug_print_rule_group_build_details");
            tmpval = table_api.add_option("debug_print_rule_group_build_details", true);
        }
        else if (keyword == "debug-print-fast-pattern")
        {
            table_api.add_diff_option_comment("debug-print-fast-pattern", "show_fast_patterns");
            tmpval = table_api.add_option("show_fast_patterns", true);
        }
        else if (keyword == "max_queue_events")
        {
            std::string val;

            if (util::get_string(data_stream, val, ", "))
                tmpval = table_api.add_option("max_queue_events", std::stoi(val));
            else
                tmpval = false;
        }
        else if (keyword == "max-pattern-len")
        {
            std::string val;
            table_api.add_diff_option_comment("max-pattern-len", "max_pattern_len");

            if (util::get_string(data_stream, val, ", "))
                tmpval = table_api.add_option("max_pattern_len", std::stoi(val));
            else
                tmpval = false;
        }
        else if (keyword == "bleedover-port-limit")
        {
            std::string val;
            table_api.add_diff_option_comment("bleedover-port-limit", "bleedover_port_limit");

            if (util::get_string(data_stream, val, ", "))
                tmpval = table_api.add_option("max_pattern_len", std::stoi(val));
            else
                tmpval = false;
        }
        else if (keyword == "search-method")
        {
            table_api.add_diff_option_comment("search-method", "search_method");
            std::string method;

            if (!util::get_string(data_stream, method, ", "))
            {
                retval = false;
                continue;
            }

            if (method == "mwm")
                table_api.add_deleted_comment("mwm");

            else if (method == "ac")
            {
                table_api.add_diff_option_comment("ac", "ac_full");
                tmpval = table_api.add_option("search_method", "ac_full");
            }
            else if (method == "ac-q")
            {
                table_api.add_diff_option_comment("ac-q", "ac_full");
                tmpval = table_api.add_option("search_method", "ac_full");
            }
            else if (method == "ac-nq")
            {
                table_api.add_diff_option_comment("ac-nq", "ac_full");
                tmpval = table_api.add_option("search_method", "ac_full");
            }
            else if (method == "ac-bnfa")
            {
                table_api.add_diff_option_comment("ac-bnfa", "ac_bnfa");
                tmpval = table_api.add_option("search_method", "ac_bnfa");
            }
            else if (method == "ac-bnfa-q")
            {
                table_api.add_diff_option_comment("ac-bnfa-q", "ac_bnfa");
                tmpval = table_api.add_option("search_method", "ac_bnfa");
            }
            else if (method == "ac-bnfa-nq")
            {
                table_api.add_diff_option_comment("ac-bnfa-nq", "ac_bnfa");
                tmpval = table_api.add_option("search_method", "ac_bnfa");
            }
            else if (method == "intel-cpm")
            {
                table_api.add_diff_option_comment("intel-cpm", "hyperscan");
                tmpval = table_api.add_option("search_method", "hyperscan");
            }
            else if (method == "ac-std")
            {
                table_api.add_diff_option_comment("ac-std", "ac_std");
                tmpval = table_api.add_option("search_method", "ac_std");
            }
            else if (method == "ac-banded")
            {
                table_api.add_diff_option_comment("ac-banded", "ac_banded");
                tmpval = table_api.add_option("search_method", "ac_banded");
            }
            else if (method == "acs")
            {
                table_api.add_diff_option_comment("acs", "ac_sparse");
                tmpval = table_api.add_option("search_method", "ac_sparse");
            }
            else if (method == "ac-sparsebands")
            {
                table_api.add_diff_option_comment("ac-sparsebands", "ac_sparse_bands");
                tmpval = table_api.add_option("search_method", "ac_sparse_bands");
            }
            else if (method == "lowmem")
            {
                tmpval = table_api.add_option("search_method", "lowmem");
            }
            else if (method == "lowmem-q")
            {
                table_api.add_diff_option_comment("lowmem-q", "lowmem");
                tmpval = table_api.add_option("search_method", "lowmem");
            }
            else if (method == "lowmem-nq")
            {
                table_api.add_diff_option_comment("lowmem-nq", "lowmem");
                tmpval = table_api.add_option("search_method", "lowmem");
            }
            else if (method == "ac-split")
            {
                table_api.add_diff_option_comment("ac-split", "split_any_any");
                table_api.add_diff_option_comment("ac-split", "ac_full");
                bool tmpval2 = table_api.add_option("split_any_any", true);
                bool tmpval1 = table_api.add_option("search_method", "ac_full");
                split_set = true;
                tmpval = tmpval1 && tmpval2;

                if (!table_api.add_option("split_any_any", true))
                    tmpval = false;
            }
            else
            {
                tmpval = false;
            }
        }
        else
            tmpval = false;

        if (retval && !tmpval)
            retval = false;
    }
    if ( !split_set )
    {
        table_api.add_diff_option_comment("split-any-any", "split_any_any = true by default");
        table_api.add_option("split_any_any", false);
    }

    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new Detection(c);
}

static const ConvertMap detection_api =
{
    "detection",
    ctor,
};

const ConvertMap* detection_map = &detection_api;
} // namespace config

