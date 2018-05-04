//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

// FIXIT-M This will be refactored soon

#include "framework/counts.h"
#include "main/thread.h"

#include "file_api.h"
#include "file_config.h"

#define MAX_PROTOCOL_ORDINAL 8192  // FIXIT-L use std::vector and get_protocol_count()

struct FileCounts
{
    PegCount files_total;
    PegCount file_data_total;
    PegCount cache_add_fails;
    PegCount files_buffered_total;
    PegCount files_released_total;
    PegCount files_freed_total;
    PegCount files_captured_total;
    PegCount file_memcap_failures_total;
    PegCount file_memcap_failures_reserve;  // This happens during reserve
    PegCount file_reserve_failures;         // This happens during reserve
    PegCount file_size_min;                 // This happens during reserve
    PegCount file_size_max;                 // This happens during reserve
    PegCount file_within_packet;
    PegCount file_buffers_used_max;         // maximum buffers used simultaneously
    PegCount file_buffers_allocated_total;
    PegCount file_buffers_freed_total;
    PegCount file_buffers_released_total;
    PegCount file_buffers_free_errors;
    PegCount file_buffers_release_errors;
};

struct FileStats
{
    PegCount files_processed[FILE_ID_MAX + 1][2];
    PegCount signatures_processed[FILE_ID_MAX + 1][2];
    PegCount verdicts_type[FILE_VERDICT_MAX];
    PegCount verdicts_signature[FILE_VERDICT_MAX];
    PegCount files_by_proto[MAX_PROTOCOL_ORDINAL + 1];
    PegCount signatures_by_proto[MAX_PROTOCOL_ORDINAL + 1];
    PegCount data_processed[FILE_ID_MAX + 1][2];
};

extern THREAD_LOCAL FileCounts file_counts;
extern THREAD_LOCAL FileStats* file_stats;

void file_stats_init();
void file_stats_term();

void file_stats_sum();
void file_stats_print();

#endif

