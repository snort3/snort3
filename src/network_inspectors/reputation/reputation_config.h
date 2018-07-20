//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

#ifndef REPUTATION_CONFIG_H
#define REPUTATION_CONFIG_H

#include "framework/counts.h"
#include "main/thread.h"
#include "sfrt/sfrt_flat.h"

#include <vector>
#include <set>
#include <string>

#define NUM_INDEX_PER_ENTRY 4

// Configuration for reputation network inspector

enum NestedIP
{
    INNER,
    OUTER,
    ALL 
};

enum WhiteAction
{
    UNBLACK,
    TRUST
};

enum IPdecision
{
    DECISION_NULL,
    BLACKLISTED,
    WHITELISTED_TRUST,
    MONITORED,
    WHITELISTED_UNBLACK,
    DECISION_MAX
};

#define MAX_NUM_ZONES             UINT32_MAX
#define MAX_LIST_ID               UINT32_MAX

struct ListFile
{
    std::string file_name;
    int file_type;
    uint32_t list_id;
    bool all_zones_enabled = false;
    std::set<unsigned int> zones;
    uint8_t list_index;
    uint8_t list_type;
};

typedef std::vector<ListFile*> ListFiles;

struct ReputationConfig
{
    uint32_t memcap = 500;
    int num_entries = 0;
    bool scanlocal = false;
    IPdecision priority = WHITELISTED_TRUST;
    NestedIP nested_ip = INNER;
    WhiteAction white_action = UNBLACK;
    std::string blacklist_path;
    std::string whitelist_path;
    bool memcap_reached = false;
    uint8_t* reputation_segment = nullptr;
    table_flat_t* ip_list = nullptr;
    ListFiles list_files;
    std::string list_dir;

    ~ReputationConfig();
};

struct IPrepInfo
{
    char list_indexes[NUM_INDEX_PER_ENTRY];
    MEM_OFFSET next;
};

struct ReputationStats
{
    PegCount packets;
    PegCount blacklisted;
    PegCount whitelisted;
    PegCount monitored;
    PegCount memory_allocated;
};

extern const PegInfo reputation_peg_names[];
extern THREAD_LOCAL ReputationStats reputationstats;
#endif

