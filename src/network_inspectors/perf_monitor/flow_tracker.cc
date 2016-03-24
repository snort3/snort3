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

// flow_tracker.cc author Carter Waxman <cwaxman@cisco.com>

#include "flow_tracker.h"
#include "perf_module.h"

#include "utils/util.h"

THREAD_LOCAL FlowTracker* perf_flow;

FlowTracker::FlowTracker(SFPERF* perf) : PerfTracker(perf,
        perf->perf_flags & SFPERF_SUMMARY_FLOW,
        perf->output == PERF_FILE ? FLOW_FILE : nullptr) { }

FlowTracker::~FlowTracker()
{
    if (sfFlow.pktLenCnt)
    {
        free(sfFlow.pktLenCnt);
        sfFlow.pktLenCnt = nullptr;
    }

    if (sfFlow.portTcpSrc)
    {
        free(sfFlow.portTcpSrc);
        sfFlow.portTcpSrc = nullptr;
    }

    if (sfFlow.portTcpDst)
    {
        free(sfFlow.portTcpDst);
        sfFlow.portTcpDst = nullptr;
    }

    if (sfFlow.portUdpSrc)
    {
        free(sfFlow.portUdpSrc);
        sfFlow.portUdpSrc = nullptr;
    }

    if (sfFlow.portUdpDst)
    {
        free(sfFlow.portUdpDst);
        sfFlow.portUdpDst = nullptr;
    }

    if (sfFlow.typeIcmp)
    {
        free(sfFlow.typeIcmp);
        sfFlow.typeIcmp = nullptr;
    }
}

void FlowTracker::reset()
{
    static THREAD_LOCAL bool first = true;

    if (first)
    {
        sfFlow.pktLenCnt = (uint64_t*)SnortAlloc(sizeof(uint64_t) * (SF_MAX_PKT_LEN + 2));
        sfFlow.portTcpSrc = (uint64_t*)SnortAlloc(sizeof(uint64_t) * (SF_MAX_PORT+1));
        sfFlow.portTcpDst = (uint64_t*)SnortAlloc(sizeof(uint64_t) * (SF_MAX_PORT+1));
        sfFlow.portUdpSrc = (uint64_t*)SnortAlloc(sizeof(uint64_t) * (SF_MAX_PORT+1));
        sfFlow.portUdpDst = (uint64_t*)SnortAlloc(sizeof(uint64_t) * (SF_MAX_PORT+1));
        sfFlow.typeIcmp = (uint64_t*)SnortAlloc(sizeof(uint64_t) * 256);

        if ( config->format == PERF_CSV )
            LogFlowPerfHeader(fh);

        first = false;
    }
    else
    {
        memset(sfFlow.pktLenCnt, 0, sizeof(uint64_t) * (SF_MAX_PKT_LEN + 2));
        memset(sfFlow.portTcpSrc, 0, sizeof(uint64_t) * (SF_MAX_PORT+1));
        memset(sfFlow.portTcpDst, 0, sizeof(uint64_t) * (SF_MAX_PORT+1));
        memset(sfFlow.portUdpSrc, 0, sizeof(uint64_t) * (SF_MAX_PORT+1));
        memset(sfFlow.portUdpDst, 0, sizeof(uint64_t) * (SF_MAX_PORT+1));
        memset(sfFlow.typeIcmp, 0, sizeof(uint64_t) * 256);
    }

    sfFlow.pktTotal = 0;
    sfFlow.byteTotal = 0;

    sfFlow.portTcpHigh=0;
    sfFlow.portTcpTotal=0;

    sfFlow.portUdpHigh=0;
    sfFlow.portUdpTotal=0;

    sfFlow.typeIcmpTotal = 0;
}

void FlowTracker::update(Packet* p)
{
    if (!p->is_rebuilt())
        UpdateFlowStats(&sfFlow, p);
}

void FlowTracker::process(bool summarize)
{
    if (summarize && !summary)
        return;

    ProcessFlowStats(&sfFlow, fh, config->format, cur_time);

    if ( !summary )
        reset();
}

