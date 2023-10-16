//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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

// fp_config.h is derived from fpcreate.h by:
//
// Dan Roelker <droelker@sourcefire.com>
// Marc Norton <mnorton@sourcefire.com>

#ifndef FP_CONFIG_H
#define FP_CONFIG_H

#include <string>

namespace snort
{
    struct MpseApi;
}

// this is a basically a factory for creating MPSE

#define PL_BLEEDOVER_WARNINGS_ENABLED        0x01
#define PL_DEBUG_PRINT_NC_DETECT_RULES       0x02
#define PL_DEBUG_PRINT_RULEGROUP_BUILD       0x04
#define PL_DEBUG_PRINT_RULEGROUPS_UNCOMPILED 0x08
#define PL_DEBUG_PRINT_RULEGROUPS_COMPILED   0x10
#define PL_SINGLE_RULE_GROUP                 0x20

class FastPatternConfig
{
public:
    FastPatternConfig();

    void set_debug_mode()
    { debug = true; }

    bool get_debug_mode() const
    { return debug; }

    void set_stream_insert(bool enable)
    { inspect_stream_insert = enable; }

    bool get_stream_insert() const
    { return inspect_stream_insert; }

    void set_max_queue_events(unsigned num_events)
    { max_queue_events = num_events; }

    unsigned get_max_queue_events() const
    { return max_queue_events; }

    void set_bleed_over_port_limit(unsigned n)
    { bleedover_port_limit = n; }

    int get_bleed_over_port_limit() const
    { return bleedover_port_limit; }

    int get_single_rule_group() const
    { return portlists_flags & PL_SINGLE_RULE_GROUP; }

    int get_bleed_over_warnings() const
    { return portlists_flags & PL_BLEEDOVER_WARNINGS_ENABLED; }

    int get_debug_print_nc_rules() const
    { return portlists_flags & PL_DEBUG_PRINT_NC_DETECT_RULES; }

    int get_debug_print_rule_group_build_details() const
    { return portlists_flags & PL_DEBUG_PRINT_RULEGROUP_BUILD; }

    int get_debug_print_rule_groups_compiled() const
    { return portlists_flags & PL_DEBUG_PRINT_RULEGROUPS_COMPILED; }

    int get_debug_print_rule_groups_uncompiled() const
    { return portlists_flags & PL_DEBUG_PRINT_RULEGROUPS_UNCOMPILED; }

    void set_debug_print_fast_patterns(bool b)
    { debug_print_fast_pattern = b; }

    bool get_debug_print_fast_patterns() const
    { return debug_print_fast_pattern; }

    void set_split_any_any(bool enable)
    { split_any_any = enable; }

    bool get_split_any_any() const
    { return split_any_any; }

    void set_single_rule_group()
    { portlists_flags |= PL_SINGLE_RULE_GROUP; }

    void set_bleed_over_warnings()
    { portlists_flags |= PL_BLEEDOVER_WARNINGS_ENABLED; }

    void set_debug_print_nc_rules()
    { portlists_flags |= PL_DEBUG_PRINT_NC_DETECT_RULES; }

    void set_debug_print_rule_group_build_details()
    { portlists_flags |= PL_DEBUG_PRINT_RULEGROUP_BUILD; }

    void set_debug_print_rule_groups_compiled()
    { portlists_flags |= PL_DEBUG_PRINT_RULEGROUPS_COMPILED; }

    void set_debug_print_rule_groups_uncompiled()
    { portlists_flags |= PL_DEBUG_PRINT_RULEGROUPS_UNCOMPILED; }

    void set_rule_db_dir(const char* s)
    { rule_db_dir = s; }

    const std::string& get_rule_db_dir() const
    { return rule_db_dir; }

    bool set_search_method(const char*);
    const char* get_search_method();

    bool set_offload_search_method(const char*);
    void set_max_pattern_len(unsigned);
    void set_queue_limit(unsigned);

    unsigned get_queue_limit() const
    { return queue_limit; }

    const snort::MpseApi* get_search_api() const
    { return search_api; }

    const snort::MpseApi* get_offload_search_api() const
    { return offload_search_api; }

    int get_num_patterns_truncated() const
    { return num_patterns_truncated; }

    unsigned set_max(unsigned bytes);

    bool deduplicate() const
    { return dedup; }

private:
    const snort::MpseApi* search_api = nullptr;
    const snort::MpseApi* offload_search_api = nullptr;

    bool inspect_stream_insert = true;
    bool split_any_any = false;
    bool debug_print_fast_pattern = false;
    bool debug = false;
    bool dedup = true;

    unsigned max_queue_events = 5;
    unsigned bleedover_port_limit = 1024;
    unsigned max_pattern_len = 0;

    unsigned queue_limit = 0;

    int portlists_flags = 0;
    unsigned num_patterns_truncated = 0;  // due to max_pattern_len

    std::string rule_db_dir;
};

#endif

