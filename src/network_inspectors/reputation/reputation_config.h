//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
#include "main/snort_debug.h"
#include "main/thread.h"
#include "sfrt/sfrt_flat.h"

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

struct ListInfo
{
    uint8_t listIndex;
    uint8_t listType;
    uint32_t listId;
};

struct ReputationConfig
{
    uint32_t memcap = 500;
    int numEntries = 0;
    bool scanlocal = false;
    IPdecision priority = WHITELISTED_TRUST;
    NestedIP nestedIP = INNER;
    WhiteAction whiteAction = UNBLACK;
    MEM_OFFSET local_black_ptr = 0;
    MEM_OFFSET local_white_ptr = 0;
    uint8_t* reputation_segment = nullptr;
    char* blacklist_path = nullptr;
    char* whitelist_path = nullptr;
    bool memCapReached = false;
    table_flat_t* iplist = nullptr;
    ListInfo* listInfo = nullptr;

    ~ReputationConfig();
};

struct IPrepInfo
{
    char listIndexes[NUM_INDEX_PER_ENTRY];
    MEM_OFFSET next;
};

DEBUG_WRAP(void ReputationPrintRepInfo(IPrepInfo* repInfo, uint8_t* base); )

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

