//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_debug.h"
extern Trace TRACE_NAME(detection);

namespace snort
{
struct Packet;
struct SnortConfig;
struct XHash;
}
struct RuleLatencyState;

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
};

struct detection_option_tree_node_t
{
    eval_func_t evaluate;
    int is_relative;
    int num_children;
    int relative_children;
    void* option_data;
    option_type_t option_type;
    detection_option_tree_node_t** children;
    dot_node_state_t* state;
};

struct detection_option_tree_root_t
{
    int num_children;
    detection_option_tree_node_t** children;
    RuleLatencyState* latency_state;

    struct OptTreeNode* otn;  // first rule in tree
};

struct detection_option_eval_data_t
{
    void* pomd;
    void* pmd;
    snort::Packet* p;
    char flowbit_failed;
    char flowbit_noalert;
};

// return existing data or add given and return nullptr
void* add_detection_option(struct snort::SnortConfig*, option_type_t, void*);
void* add_detection_option_tree(struct snort::SnortConfig*, detection_option_tree_node_t*);

int detection_option_node_evaluate(
    detection_option_tree_node_t*, detection_option_eval_data_t*, class Cursor&);

void DetectionHashTableFree(snort::XHash*);
void DetectionTreeHashTableFree(snort::XHash*);

void print_option_tree(detection_option_tree_node_t*, int level);
void detection_option_tree_update_otn_stats(snort::XHash*);

detection_option_tree_root_t* new_root(OptTreeNode*);
void free_detection_option_root(void** existing_tree);

detection_option_tree_node_t* new_node(option_type_t, void*);
void free_detection_option_tree(detection_option_tree_node_t*);

#endif

