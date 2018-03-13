//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// flow_tracker.h author Carter Waxman <cwaxman@cisco.com>

#ifndef FLOW_TRACKER_H
#define FLOW_TRACKER_H

#include "perf_tracker.h"

struct FlowProto
{
    std::vector<PegCount> src;
    std::vector<PegCount> dst;
    PegCount high = 0;
};

class FlowTracker : public PerfTracker
{
public:
    FlowTracker(PerfConfig* perf);

    void update(snort::Packet*) override;
    void process(bool) override;

protected:
    virtual void clear();

private:
    PegCount byte_total = 0;

    std::vector<PegCount> pkt_len_cnt;
    PegCount pkt_len_oversize_cnt = 0;

    FlowProto udp;
    FlowProto tcp;

    std::vector<PegCount> type_icmp;

    void update_transport_flows(int sport, int dport,
        FlowProto& proto, int len);
};

#endif

