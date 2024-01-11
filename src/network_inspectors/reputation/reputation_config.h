//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
#include "sfrt/sfrt.h"

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

enum AllowAction
{
    DO_NOT_BLOCK,
    TRUST
};

enum IPdecision
{
    DECISION_NULL,
    BLOCKED,
    TRUSTED,
    MONITORED,
    BLOCKED_SRC,
    BLOCKED_DST,
    TRUSTED_SRC,
    TRUSTED_DST,
    TRUSTED_DO_NOT_BLOCK,
    MONITORED_SRC,
    MONITORED_DST,
    DECISION_MAX
};

#define MAX_NUM_INTFS             INT32_MAX
#define MAX_LIST_ID               UINT32_MAX

struct ListFile
{
    std::string file_name;
    int file_type;
    uint32_t list_id;
    bool all_intfs_enabled = false;
    std::set<unsigned int> intfs;
    uint8_t list_index;
    uint8_t list_type;
};

typedef std::vector<ListFile*> ListFiles;

struct ReputationConfig
{
    uint32_t memcap = 500;
    bool scanlocal = false;
    IPdecision priority = TRUSTED;
    NestedIP nested_ip = INNER;
    AllowAction allow_action = DO_NOT_BLOCK;
    std::string blocklist_path;
    std::string allowlist_path;
    std::string list_dir;
};

struct IPrepInfo
{
    char list_indexes[NUM_INDEX_PER_ENTRY];
    MEM_OFFSET next;
};

struct ReputationStats
{
    PegCount packets;
    PegCount blocked;
    PegCount trusted;
    PegCount monitored;
    PegCount memory_allocated;
    PegCount aux_ip_blocked;
    PegCount aux_ip_trusted;
    PegCount aux_ip_monitored;
};

extern const PegInfo reputation_peg_names[];
extern THREAD_LOCAL ReputationStats reputationstats;

#endif

