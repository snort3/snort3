//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// Eval, profiling, and ppm data are attached in an array sized per max
// packet threads.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/time.h>
#include "main/snort_types.h"
#include "detection/rule_option_types.h"

struct Packet;
struct SFXHASH;

typedef int (* eval_func_t)(void* option_data, class Cursor&, Packet*);

// this is per packet thread
struct dot_node_state_t
{
    int result;
    struct
    {
        struct timeval ts;
        uint64_t packet_number;
        uint32_t rebuild_flag;
        char result;
        char flowbit_failed;
    } last_check;

#ifdef PERF_PROFILING
    uint64_t ticks;
    uint64_t ticks_match;
    uint64_t ticks_no_match;
    uint64_t checks;
    uint64_t disables;
#endif
#ifdef PPM_MGR
    uint64_t ppm_disable_cnt;
    uint64_t ppm_enable_cnt;
#endif
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

// this is per packet thread
#ifdef PPM_MGR
struct dot_root_state_t
{
    uint64_t ppm_suspend_time;
    uint64_t ppm_disable_cnt;
    bool enabled;
};
#endif

struct detection_option_tree_root_t
{
    int num_children;
    detection_option_tree_node_t** children;
#ifdef PPM_MGR
    dot_root_state_t* state;
#endif
};

struct detection_option_eval_data_t
{
    void* pomd;
    void* pmd;
    Packet* p;
    char flowbit_failed;
    char flowbit_noalert;
};

int add_detection_option(
    struct SnortConfig*, option_type_t type, void* option_data, void** existing_data);

int add_detection_option_tree(
    struct SnortConfig*, detection_option_tree_node_t* option_tree, void** existing_data);

int detection_option_node_evaluate(
detection_option_tree_node_t*, detection_option_eval_data_t*, class Cursor&);

void DetectionHashTableFree(SFXHASH*);
void DetectionTreeHashTableFree(SFXHASH*);
#ifdef DEBUG_OPTION_TREE
void print_option_tree(detection_option_tree_node_t* node, int level);
#endif
#ifdef PERF_PROFILING
void detection_option_tree_update_otn_stats(SFXHASH*);
#endif

detection_option_tree_root_t* new_root();
void free_detection_option_root(void** existing_tree);

detection_option_tree_node_t* new_node(option_type_t type, void* data);
void free_detection_option_tree(detection_option_tree_node_t* node);

#endif

