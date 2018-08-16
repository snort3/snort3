//--------------------------------------------------------------------------
// Copyright (C) 2017-2018 Cisco and/or its affiliates. All rights reserved.
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

// detect_trace.h author Maya Dagon

#ifndef DETECT_TRACE_H
#define DETECT_TRACE_H

// Detection trace utility

#include "framework/cursor.h"
#include "main/snort_types.h"

namespace snort
{
    struct Packet;
}

struct detection_option_tree_node_t;
struct PatternMatchData;

enum
{
    TRACE_DETECTION_ENGINE = 0x1,
    TRACE_RULE_EVAL = 0x2,
    TRACE_BUFFER_MINIMAL = 0x4,
    TRACE_BUFFER_VERBOSE = 0x8,
    TRACE_RULE_VARS = 0x10,
    TRACE_FP_SEARCH = 0x20,
    TRACE_PKT_DETECTION = 0x40,
    TRACE_OPTION_TREE = 0x80,
    TRACE_TAG = 0x100,
};

void clear_trace_cursor_info();
void print_pkt_info(snort::Packet* p);
void print_pattern(const PatternMatchData* pmd);
void dump_buffer(const uint8_t* buff, unsigned len, snort::Packet*);
void node_eval_trace(const detection_option_tree_node_t* node, const Cursor& cursor, snort::Packet*);

#endif

