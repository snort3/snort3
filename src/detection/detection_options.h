//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2007-2013 Sourcefire, Inc.
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

// detection_options.h author Steven Sturges <ssturges@cisco.com>

#ifndef DETECTION_OPTIONS_H
#define DETECTION_OPTIONS_H

// Support functions for rule option tree
//
// This implements tree processing for rule options, evaluating common
// detection options only once per pattern match.
//
// These trees are instantiated at parse time, one per MPSE match state.
// Eval, profiling, and latency data are attached in an array sized per max
// packet threads.

#include <sys/time.h>

#include "detection/rule_option_types.h"
#include "time/clock_defs.h"
#include "trace/trace_api.h"

namespace snort
{
class HashNode;
class IpsOption;
class XHash;
struct Packet;
struct SnortConfig;
}
struct RuleLatencyState;
struct SigInfo;
struct OtnState;

typedef int (* eval_func_t)(void* option_data, class Cursor&, snort::Packet*);

// this is per packet thread
struct dot_node_state_t
{
    int result;
    struct
    {
        struct timeval ts;
        uint64_t context_num;
        uint32_t rebuild_flag;
        uint16_t run_num;
        char result;
        char flowbit_failed;
    } last_check;
    void* conts;
    uint64_t context_num;
    uint16_t run_num;

    // FIXIT-L perf profiler stuff should be factored of the node state struct
    hr_duration elapsed;
    hr_duration elapsed_match;
    hr_duration elapsed_no_match;
    uint64_t checks;
    uint64_t disables;

    unsigned latency_timeouts;
    unsigned latency_suspends;

    // FIXIT-L perf profiler stuff should be factored of the node state struct
    void update(hr_duration delta, bool match)
    {
        elapsed += delta;

        if ( match )
            elapsed_match += delta;
        else
            elapsed_no_match += delta;

        ++checks;
    }

    void reset_profiling()
    {
        elapsed = elapsed_match = elapsed_no_match = 0_ticks;
        checks = disables = 0;
        latency_suspends = latency_timeouts = 0;
    }
};

struct detection_option_tree_node_t;

struct detection_option_tree_bud_t
{
    int relative_children;
    int num_children;
    detection_option_tree_node_t** children;
    const struct OptTreeNode* otn;

    detection_option_tree_bud_t()
        : relative_children(0), num_children(0), children(nullptr), otn(nullptr) {}

    detection_option_tree_bud_t(int num, detection_option_tree_node_t** d_otn, const OptTreeNode* r_otn)
        : relative_children(0), num_children(num), children(d_otn), otn(r_otn) {}
};

struct detection_option_tree_node_t : public detection_option_tree_bud_t
{
    eval_func_t evaluate;
    void* option_data;
    dot_node_state_t* state;
    int is_relative;
    option_type_t option_type;
};

struct detection_option_tree_root_t : public detection_option_tree_bud_t
{
    RuleLatencyState* latency_state;

    detection_option_tree_root_t()
        : detection_option_tree_bud_t(), latency_state(nullptr) {}

    detection_option_tree_root_t(int num, detection_option_tree_node_t** d_otn, const OptTreeNode* r_otn,
        RuleLatencyState* lat)
        : detection_option_tree_bud_t(num, d_otn, r_otn), latency_state(lat) {}
};

struct detection_option_eval_data_t
{
    const void* pmd;
    snort::Packet* p;
    snort::IpsOption* buf_selector;
    const struct OptTreeNode* otn;  // first rule in current processed tree
    char leaf_reached;
    char flowbit_failed;
    char flowbit_noalert;

    detection_option_eval_data_t()
        : pmd(nullptr), p(nullptr), buf_selector(nullptr), otn(nullptr)
        , leaf_reached(0), flowbit_failed(0), flowbit_noalert(0) {}

    detection_option_eval_data_t(snort::Packet* packet, const OptTreeNode* otn,
        const void* match_data = nullptr) : pmd(match_data), p(packet), buf_selector(nullptr)
        , otn(otn), leaf_reached(0), flowbit_failed(0), flowbit_noalert(0) {}

    detection_option_eval_data_t(const detection_option_eval_data_t& m)
        : pmd(m.pmd), p(m.p), buf_selector(m.buf_selector), otn(m.otn)
        , leaf_reached(m.leaf_reached), flowbit_failed(m.flowbit_failed), flowbit_noalert(m.flowbit_noalert) {}
};

// return existing data or add given and return nullptr
void* add_detection_option(struct snort::SnortConfig*, option_type_t, void*);
void* add_detection_option_tree(struct snort::SnortConfig*, detection_option_tree_node_t*);

int detection_option_node_evaluate(
    const detection_option_tree_node_t*, detection_option_eval_data_t&, const class Cursor&);

void print_option_tree(detection_option_tree_node_t*, int level);
void detection_option_tree_update_otn_stats(std::vector<snort::HashNode*>&,
    std::unordered_map<SigInfo*, OtnState>&, unsigned);
void detection_option_tree_reset_otn_stats(std::vector<snort::HashNode*>&, unsigned);

detection_option_tree_root_t* new_root(OptTreeNode*);
void free_detection_option_root(void** existing_tree);

detection_option_tree_node_t* new_node(option_type_t, void*);
void free_detection_option_tree(detection_option_tree_node_t*);

#endif

