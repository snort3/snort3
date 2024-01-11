//--------------------------------------------------------------------------
// Copyright (C) 2022-2024 Cisco and/or its affiliates. All rights reserved.
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

// netflow.h author Michael Matirko <mmatirkoe@cisco.com>

#ifndef NETFLOW_H
#define NETFLOW_H

#include <unordered_map>
#include <vector>

#include "flow/flow_data.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "utils/util.h"

#include "netflow_cache.cc"
#include "netflow_record.h"

THREAD_LOCAL NetFlowStats netflow_stats;
THREAD_LOCAL snort::ProfileStats netflow_perf_stats;

// Used to ensure we fully populate the record; can't rely on the actual values being zero
struct RecordStatus
{
    bool src = false;
    bool dst = false;
    bool first = false;
    bool last = false;
    bool src_tos = false;
    bool dst_tos = false;
    bool bytes_sent = false;
    bool packets_sent = false;
};

// temporary cache required to dump the output
typedef std::pair<snort::SfIp, NetFlowSessionRecord> IpRecord;
typedef std::vector<IpRecord> DumpCache;
static DumpCache* dump_cache = nullptr;

struct IpCompare
{
    bool operator()(const IpRecord& a, const IpRecord& b)
    { return a.first.less_than(b.first); }
};

static std::unordered_map<int, int>* udp_srv_map = nullptr;
static std::unordered_map<int, int>* tcp_srv_map = nullptr;

#endif
