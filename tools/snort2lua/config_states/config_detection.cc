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
// config_detection.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "utils/converter.h"
#include "utils/snort2lua_util.h"

namespace config
{

namespace {

class Detection : public ConversionState
{
public:
    Detection(Converter* cv, LuaData* ld) : ConversionState(cv, ld) {};
    virtual ~Detection() {};
    virtual bool convert(std::istringstream& data_stream);
};

} // namespace

bool Detection::convert(std::istringstream& data_stream)
{

    bool retval = true;
    std::string args;

    ld->open_table("search_engine");
    ld->add_comment_to_table("This table was previous 'config detection: ...");

    while(util::get_string(data_stream, args, ", "))
    {
        bool tmpval = true;
        std::string keyword;
        std::istringstream arg_stream(args);

        if (!(arg_stream >> keyword)) // impossible to fail. get_string() will return false first.
            tmpval = false;

        else if (!keyword.compare("no_stream_inserts"))
            tmpval = ld->add_option_to_table("no_stream_inserts", true);

        else if (!keyword.compare("debug"))
            tmpval = ld->add_option_to_table("debug", true);

        else if (!keyword.compare("search-optimize"))
        {
            ld->add_diff_option_comment("search-optimize", "search_optimize");
            tmpval = ld->add_option_to_table("search_optimize", true);
        }

        else if (!keyword.compare("split-any-any"))
        {
            ld->add_diff_option_comment("split-any-any", "split_any_any");
            tmpval = ld->add_option_to_table("split_any_any", true);
        }

        else if(!keyword.compare("bleedover-warnings-enabled"))
        {
            ld->add_diff_option_comment("bleedover-warnings-enabled", "bleedover_warnings_enabled");
            tmpval = ld->add_option_to_table("bleedover_warnings_enabled", true);
        }

        else if(!keyword.compare("enable-single-rule-group"))
        {
            ld->add_diff_option_comment("enable-single-rule-group", "enable_single_rule_group");
            tmpval = ld->add_option_to_table("enable_single_rule_group", true);
        }

        else if(!keyword.compare("debug-print-nocontent-rule-tests"))
        {
            ld->add_diff_option_comment("debug-print-nocontent-rule-tests", "debug_print_nocontent_rule_tests");
            tmpval = ld->add_option_to_table("debug_print_nocontent_rule_tests", true);
        }

        else if(!keyword.compare("debug-print-rule-groups-compiled"))
        {
            ld->add_diff_option_comment("debug-print-rule-groups-compiled", "debug_print_rule_groups_compiled");
            tmpval = ld->add_option_to_table("debug_print_rule_groups_compiled", true);
        }

        else if(!keyword.compare("debug-print-rule-groups-uncompiled"))
        {
            ld->add_diff_option_comment("debug-print-rule-groups-uncompiled", "debug_print_rule_groups_uncompiled");
            tmpval = ld->add_option_to_table("debug_print_rule_groups_uncompiled", true);
        }

        else if(!keyword.compare("debug-print-rule-group-build-details"))
        {
            ld->add_diff_option_comment("debug-print-rule-group-build-details", "debug_print_rule_group_build_details");
            tmpval = ld->add_option_to_table("debug_print_rule_group_build_details", true);
        }

        else if(!keyword.compare("debug-print-fast-pattern"))
        {
            ld->add_diff_option_comment("debug-print-fast-pattern", "debug_print_fast_pattern");
            tmpval = ld->add_option_to_table("debug_print_fast_pattern", true);
        }

        else if(!keyword.compare("max_queue_events"))
        {
            std::string val;

            if (util::get_string(data_stream, val, ", "))
                tmpval = ld->add_option_to_table("max_queue_events", std::stoi(val));
            else
                tmpval = false;
        }

        else if(!keyword.compare("max-pattern-len"))
        {
            std::string val;
            ld->add_diff_option_comment("max-pattern-len", "max_pattern_len");

            if (util::get_string(data_stream, val, ", "))
                tmpval = ld->add_option_to_table("max_pattern_len", std::stoi(val));
            else
                tmpval = false;
        }

        else if(!keyword.compare("bleedover-port-limit"))
        {
            std::string val;
            ld->add_diff_option_comment("bleedover-port-limit", "bleedover_port_limit");

            if (util::get_string(data_stream, val, ", "))
                tmpval = ld->add_option_to_table("max_pattern_len", std::stoi(val));
            else
                tmpval = false;
        }

        else if (!keyword.compare("search-method"))
        {
            ld->add_diff_option_comment("search-method", "search_method");
            std::string method;

            if (!util::get_string(data_stream, method, ", "))
            {
                retval = false;
                continue;
            }


            if (!method.compare("mwm"))
                ld->add_deleted_comment("mwm");

            else if (!method.compare("ac"))
            {
                ld->add_diff_option_comment("ac", "ac_full_q");
                tmpval = ld->add_option_to_table("search_method", "ac_full_q");
            }

            else if (!method.compare("ac-q"))
            {
                ld->add_diff_option_comment("ac-q", "ac_full_q");
                tmpval = ld->add_option_to_table("search_method", "ac_full_q");
            }

            else if (!method.compare("ac-nq"))
            {
                ld->add_diff_option_comment("ac-nq", "ac_full");
                tmpval = ld->add_option_to_table("search_method", "ac_full");
            }

            else if (!method.compare("ac-bnfa"))
            {
                ld->add_diff_option_comment("ac-bnfa", "ac_bnfa_q");
                tmpval = ld->add_option_to_table("search_method", "ac_bnfa_q");
            }

            else if (!method.compare("ac-bnfa-q"))
            {
                ld->add_diff_option_comment("ac-bnfa-q", "ac_bnfa_q");
                tmpval = ld->add_option_to_table("search_method", "ac_bnfa_q");
            }

            else if (!method.compare("ac-bnfa-nq"))
            {
                ld->add_diff_option_comment("ac-bnfa-nq", "ac_bnfa");
                tmpval = ld->add_option_to_table("search_method", "ac_bnfa");
            }

            else if (!method.compare("intel-cpm"))
            {
                ld->add_diff_option_comment("intel-cpm", "intel_cpm");
                tmpval = ld->add_option_to_table("search_method", "intel_cpm");
            }

            else if (!method.compare("ac-std"))
            {
                ld->add_diff_option_comment("ac-std", "ac_std");
                tmpval = ld->add_option_to_table("search_method", "ac_std");
            }

            else if (!method.compare("ac-banded"))
            {
                ld->add_diff_option_comment("ac-banded", "ac_banded");
                tmpval = ld->add_option_to_table("search_method", "ac_banded");
            }

            else if (!method.compare("acs"))
            {
                ld->add_diff_option_comment("acs", "ac_sparse");
                tmpval = ld->add_option_to_table("search_method", "ac_sparse");
            }

            else if (!method.compare("ac-sparsebands"))
            {
                ld->add_diff_option_comment("ac-sparsebands", "ac_sparse_bands");
                tmpval = ld->add_option_to_table("search_method", "ac_sparse_bands");
            }

            else if (!method.compare("lowmem"))
            {
                ld->add_diff_option_comment("lowmem", "lowmem_q");
                tmpval = ld->add_option_to_table("search_method", "lowmem_q");
            }

            else if (!method.compare("lowmem-q"))
            {
                ld->add_diff_option_comment("lowmem-q", "lowmem_q");
                tmpval = ld->add_option_to_table("search_method", "lowmem_q");
            }

            else if (!method.compare("lowmem-nq"))
            {
                ld->add_diff_option_comment("lowmem-nq", "lowmem");
                tmpval = ld->add_option_to_table("search_method", "lowmem");
            }

            else if (!method.compare("ac-split"))
            {
                ld->add_diff_option_comment("ac-split", "split_any_any");
                ld->add_diff_option_comment("ac-split", "ac_full_q");
                bool tmpval2 = ld->add_option_to_table("split_any_any", true);
                bool tmpval1 = ld->add_option_to_table("search_method", "ac_full_q");
                tmpval = tmpval1 && tmpval2;

                if(!ld->add_option_to_table("split_any_any", true))
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

    return retval;
}


/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter* cv, LuaData* ld)
{
    return new Detection(cv, ld);
}

static const ConvertMap detection_api =
{
    "detection",
    ctor,
};

const ConvertMap* detection_map = &detection_api;

} // namespace config
