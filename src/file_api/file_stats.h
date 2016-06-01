//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

// file_stats.h author Hui Cao <huica@cisco.com>

#ifndef FILE_STATS_H
#define FILE_STATS_H

#include <stdio.h>
#include <stdlib.h>

// FIXIT-M This will be refactored soon

#include "target_based/snort_protocols.h"
#include "target_based/sftarget_reader.h"

#include "main/snort_debug.h"
#include "file_config.h"
#include "file_api.h"

#define MAX_PROTOCOL_ORDINAL 8192  // FIXIT-L use std::vector and get_protocol_count()

typedef struct _File_Stats
{
    uint64_t files_total;
    uint64_t files_processed[FILE_ID_MAX + 1][2];
    uint64_t signatures_processed[FILE_ID_MAX + 1][2];
    uint64_t verdicts_type[FILE_VERDICT_MAX];
    uint64_t verdicts_signature[FILE_VERDICT_MAX];
    uint64_t files_by_proto[MAX_PROTOCOL_ORDINAL + 1];
    uint64_t signatures_by_proto[MAX_PROTOCOL_ORDINAL + 1];
    uint64_t data_processed[FILE_ID_MAX + 1][2];
    uint64_t file_data_total;
    uint64_t files_sig_depth;
} FileStats;

extern FileStats file_stats;

#define FILE_DEBUG_MSGS(msg) DebugMessage(DEBUG_FILE, msg)

void print_file_stats();

#endif

