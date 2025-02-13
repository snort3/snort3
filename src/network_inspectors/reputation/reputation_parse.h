//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#ifndef REPUTATION_PARSE_H
#define REPUTATION_PARSE_H

#include <cstdint>

#include "sfrt/sfrt_flat.h"

struct IPrepInfo;
struct ListFile;
struct ReputationConfig;
class ReputationData;

class ReputationParser
{
public:
    static void read_manifest(const char* filename, const ReputationConfig&, ReputationData&);
    static void add_block_allow_List(const ReputationConfig&, ReputationData&);
    static void estimate_num_entries(ReputationData&);

    void load_list_file(ListFile* list_info, const ReputationConfig& config,
        ReputationData& data);
    void ip_list_init(uint32_t max_entries, const ReputationConfig&, ReputationData&);

    unsigned get_usage() const
    { return table.sfrt_flat_usage(); }

protected:
    int duplicate_info(IPrepInfo* dest_info, IPrepInfo* current_info, uint8_t* base);
    int64_t update_entry_info_impl(INFO* current, INFO new_entry, SaveDest save_dest, uint8_t* base);
    int add_ip(snort::SfCidr* ip_addr,INFO info_ptr, const ReputationConfig& config);
    int process_line(char* line, INFO info, const ReputationConfig& config);

    static int64_t update_entry_info(INFO* current, INFO new_entry, SaveDest save_dest, uint8_t* base, void* data);

    RtTable table;
};

#endif
