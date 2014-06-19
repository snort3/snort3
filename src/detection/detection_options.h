/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2007-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**
**/

/**
**  @file        detection_options.h
**
**  @author      Steven Sturges
**
**  @brief       Support functions for rule option tree
**
**  This implements tree processing for rule options, evaluating common
**  detection options only once per pattern match.
**
*/

#ifndef DETECTION_OPTIONS_H
#define DETECTION_OPTIONS_H

#include "snort_types.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "protocols/packet.h"
#include "hash/sfxhash.h"
#include "detection/rule_option_types.h"
#include "detection/detection_defines.h"
#include "hash/sfhashfcn.h"

typedef int (*eval_func_t)(void* option_data, struct Cursor&, Packet*);

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

typedef struct _detection_option_tree_node
{
    eval_func_t evaluate;
    int is_relative;
    int num_children;
    int relative_children;
    void *option_data;
    option_type_t option_type;
    struct _detection_option_tree_node **children;
    dot_node_state_t* state;
} detection_option_tree_node_t;

#ifdef PPM_MGR
struct dot_root_state_t
{
    uint64_t ppm_suspend_time;
    uint64_t ppm_disable_cnt;
    bool enabled;
};
#endif

typedef struct _detection_option_tree_root
{
    int num_children;
    detection_option_tree_node_t **children;
#ifdef PPM_MGR
    dot_root_state_t* state;
#endif
} detection_option_tree_root_t;

typedef struct _detection_option_eval_data
{
    void *pomd;
    void *pmd;
    Packet *p;
    char flowbit_failed;
    char flowbit_noalert;
} detection_option_eval_data_t;

int add_detection_option(
    struct SnortConfig*, option_type_t type, void *option_data, void **existing_data);

int add_detection_option_tree(
    struct SnortConfig*, detection_option_tree_node_t *option_tree, void **existing_data);

int detection_option_node_evaluate(
    detection_option_tree_node_t *node, detection_option_eval_data_t *eval_data, struct Cursor&);

void DetectionHashTableFree(SFXHASH *);
void DetectionTreeHashTableFree(SFXHASH *);
#ifdef DEBUG_OPTION_TREE
void print_option_tree(detection_option_tree_node_t *node, int level);
#endif
#ifdef PERF_PROFILING
void detection_option_tree_update_otn_stats(SFXHASH *);
#endif

detection_option_tree_root_t* new_root();
void free_detection_option_root(void **existing_tree);

detection_option_tree_node_t* new_node(option_type_t type, void* data);
void free_detection_option_tree(detection_option_tree_node_t *node);

#endif /* DETECTION_OPTIONS_H */

