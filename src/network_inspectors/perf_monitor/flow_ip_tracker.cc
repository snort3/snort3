//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

// flow_ip_tracker.cc author Carter Waxman <cwaxman@cisco.com>

#include "flow_ip_tracker.h"
#include "perf_flow.h"
#include "perf_module.h"

#include "sfip/sf_ip.h"
#include "utils/util.h"

THREAD_LOCAL FlowIPTracker* perf_flow_ip;

sfSFSValue* FlowIPTracker::findFlowIPStats(const sfip_t* src_addr, const sfip_t* dst_addr,
    int* swapped)
{
    SFXHASH_NODE* node;
    sfSFSKey key;
    sfSFSValue* value;

    if (sfip_lesser(src_addr, dst_addr))
    {
        sfip_copy(key.ipA, src_addr);
        sfip_copy(key.ipB, dst_addr);
        *swapped = 0;
    }
    else
    {
        sfip_copy(key.ipA, dst_addr);
        sfip_copy(key.ipB, src_addr);
        *swapped = 1;
    }

    value = (sfSFSValue*)sfxhash_find(ipMap, &key);
    if (!value)
    {
        node = sfxhash_get_node(ipMap, &key);
        if (!node)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                "Key/Value pair didn't exist in the flow stats table and we couldn't add it!\n");
                );
            return nullptr;
        }
        memset(node->data, 0, sizeof(sfSFSValue));
        value = (sfSFSValue*)node->data;
    }

    return value;
}

FlowIPTracker::FlowIPTracker(SFPERF* perf) : PerfTracker(perf,
        perf->perf_flags & SFPERF_SUMMARY_FLOWIP,
        perf->flowip_file ? FLIP_FILE : nullptr)
{ }

FlowIPTracker::~FlowIPTracker()
{
    if (ipMap)
    {
        sfxhash_delete(ipMap);
        ipMap = nullptr;
    }
}

void FlowIPTracker::reset()
{
    static THREAD_LOCAL bool first = true;

    if (first)
    {
        ipMap = sfxhash_new(1021, sizeof(sfSFSKey), sizeof(sfSFSValue),
            perfmon_config->flowip_memcap, 1, nullptr, nullptr, 1);
        if (!ipMap)
            FatalError("Unable to allocate memory for FlowIP stats\n"); //FIXIT-H this should all
                                                                        // occur at thread init

        first = false;
    }
    else
        sfxhash_make_empty(ipMap);
}

void FlowIPTracker::update(Packet* p)
{
    if (p->has_ip() && !p->is_rebuilt())
    {
        SFSType type = SFS_TYPE_OTHER;
        sfSFSValue* value;
        sfBTStats* stats;
        int swapped;
        const sfip_t* src_addr = p->ptrs.ip_api.get_src();
        const sfip_t* dst_addr = p->ptrs.ip_api.get_dst();
        int len = p->pkth->caplen;

        if (p->ptrs.tcph)
            type = SFS_TYPE_TCP;
        else if (p->ptrs.udph)
            type = SFS_TYPE_UDP;

        value = findFlowIPStats(src_addr, dst_addr, &swapped);
        if (!value)
            return;

        stats = &value->trafficStats[type];

        if (!swapped)
        {
            stats->packets_AtoB++;
            stats->bytes_AtoB += len;
        }
        else
        {
            stats->packets_BtoA++;
            stats->bytes_BtoA += len;
        }
        value->total_packets++;
        value->total_bytes += len;
    }
}

void FlowIPTracker::DisplayFlowIPStats()
{
    SFXHASH_NODE* node;
    uint64_t total = 0;

    LogMessage("\n");
    LogMessage("\n");
    LogMessage("IP Flows (%d unique IP pairs)\n", sfxhash_count(ipMap));
    LogMessage("---------------\n");
    for (node = sfxhash_findfirst(ipMap); node; node = sfxhash_findnext(ipMap))
    {
        sfSFSKey* key;
        sfSFSValue* stats;
        char ipA[41], ipB[41];

        key = (sfSFSKey*)node->key;
        stats = (sfSFSValue*)node->data;

        sfip_raw_ntop(key->ipA.family, key->ipA.ip32, ipA, sizeof(ipA));
        sfip_raw_ntop(key->ipB.family, key->ipB.ip32, ipB, sizeof(ipB));
        LogMessage("[%s <-> %s]: " STDu64 " bytes in " STDu64 " packets (%u, %u, %u)\n", ipA, ipB,
            stats->total_bytes, stats->total_packets,
            stats->stateChanges[SFS_STATE_TCP_ESTABLISHED],
            stats->stateChanges[SFS_STATE_TCP_CLOSED], stats->stateChanges[SFS_STATE_UDP_CREATED]);
        total += stats->total_packets;
    }
    LogMessage("Classified " STDu64 " packets.\n", total);
}

void FlowIPTracker::WriteFlowIPStats()
{
    SFXHASH_NODE* node;

    if (!fh)
        return;

    fprintf(fh, "%u,%u\n", (uint32_t)time(nullptr), sfxhash_count(ipMap));
    for (node = sfxhash_findfirst(ipMap); node; node = sfxhash_findnext(ipMap))
    {
        sfSFSKey* key;
        sfSFSValue* stats;
        char ipA[41], ipB[41];

        key = (sfSFSKey*)node->key;
        stats = (sfSFSValue*)node->data;

        sfip_raw_ntop(key->ipA.family, key->ipA.ip32, ipA, sizeof(ipA));
        sfip_raw_ntop(key->ipB.family, key->ipB.ip32, ipB, sizeof(ipB));
        fprintf(fh, "%s,%s," CSVu64 CSVu64 CSVu64 CSVu64 CSVu64 CSVu64 CSVu64
            CSVu64 CSVu64 CSVu64 CSVu64 CSVu64 "%u,%u,%u\n",
            ipA, ipB,
            stats->trafficStats[SFS_TYPE_TCP].packets_AtoB,
            stats->trafficStats[SFS_TYPE_TCP].bytes_AtoB,
            stats->trafficStats[SFS_TYPE_TCP].packets_BtoA,
            stats->trafficStats[SFS_TYPE_TCP].bytes_BtoA,
            stats->trafficStats[SFS_TYPE_UDP].packets_AtoB,
            stats->trafficStats[SFS_TYPE_UDP].bytes_AtoB,
            stats->trafficStats[SFS_TYPE_UDP].packets_BtoA,
            stats->trafficStats[SFS_TYPE_UDP].bytes_BtoA,
            stats->trafficStats[SFS_TYPE_OTHER].packets_AtoB,
            stats->trafficStats[SFS_TYPE_OTHER].bytes_AtoB,
            stats->trafficStats[SFS_TYPE_OTHER].packets_BtoA,
            stats->trafficStats[SFS_TYPE_OTHER].bytes_BtoA,
            stats->stateChanges[SFS_STATE_TCP_ESTABLISHED],
            stats->stateChanges[SFS_STATE_TCP_CLOSED],
            stats->stateChanges[SFS_STATE_UDP_CREATED]);
    }

    fflush(fh);
}

void FlowIPTracker::process(bool summarize)
{
    if (summarize && !summary)
        return;

    if (config->perf_flags & SFPERF_CONSOLE)
        DisplayFlowIPStats();

    if (fh)
        WriteFlowIPStats();

    if ( !summary )
        reset();
}

int FlowIPTracker::updateState(const sfip_t* src_addr, const sfip_t* dst_addr, SFSState state)
{
    sfSFSValue* value;
    int swapped;

    value = findFlowIPStats(src_addr, dst_addr, &swapped);
    if (!value)
        return 1;

    value->stateChanges[state]++;

    return 0;
}

