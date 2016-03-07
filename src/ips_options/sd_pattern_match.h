//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2009-2013 Sourcefire, Inc.
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

// sd_pattern_match.h author Ryan Jordan

#ifndef SD_PATTERN_MATCH_H
#define SD_PATTERN_MATCH_H

#include <iostream>
#include <stdint.h>

#define SD_SOCIAL_PATTERN          "\\d{3}-\\d{2}-\\d{4}"
#define SD_SOCIAL_NODASHES_PATTERN "\\d{9}"
#define SD_CREDIT_PATTERN_ALL      "\\d{4} ?-?\\d{4} ?-?\\d{2} ?-?\\d{2} ?-?\\d{3}\\d?"

struct SdOptionData
{
    char *pii;
    uint32_t counter_index;
    int (*validate_func)(const uint8_t* buf, uint32_t buflen);
    uint8_t count;
    uint8_t match_success;

    SdOptionData(std::string pattern, uint8_t threshold);

    ~SdOptionData()
    {
        free(pii);
        pii = nullptr;
        validate_func = nullptr;
    }
};

struct SdTreeNode
{
    char* pattern;
    uint16_t num_children;
    uint16_t num_option_data;
    SdTreeNode** children;
    SdOptionData** option_data_list;
};

int FreePiiTree(SdTreeNode *node);

struct SdContext
{
    SdTreeNode *head_node;
    uint32_t num_patterns;

    SdContext(SdOptionData*);

    ~SdContext()
    {
        FreePiiTree(head_node);
    }
};

struct SdSessionData
{
    SdTreeNode *part_match_node;
    uint16_t part_match_index;
    uint32_t num_patterns;
    uint32_t global_counter;
    uint8_t *counters;
};

int AddPii(SdTreeNode *head, SdOptionData *data);


SdTreeNode * FindPiiRecursively(SdTreeNode *node, const uint8_t *buf, uint16_t *buf_index,
        uint16_t buflen, uint16_t *partial_index, SdTreeNode **partial_node);

SdTreeNode * FindPii(const SdTreeNode *head, const uint8_t *buf, uint16_t *buf_index,
        uint16_t buflen, SdSessionData *session);

#endif


