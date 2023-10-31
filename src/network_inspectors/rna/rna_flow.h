//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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

// rna_flow.h author Silviu Minut <sminut@cisco.com>

#ifndef RNA_FLOW_H
#define RNA_FLOW_H

#include <memory>
#include <mutex>

#include "flow/flow_data.h"
#include "host_tracker/host_tracker.h"
#include "sfip/sf_ip.h"

#include "rna_fingerprint_tcp.h"

namespace snort
{
struct Packet;
}

class DiscoveryFilter;

using RnaTracker = std::shared_ptr<snort::HostTracker>;

class RNAFlow : public snort::FlowData
{
public:
    FpFingerprintState state;

    RNAFlow() : FlowData(inspector_id) { }
    ~RNAFlow() override;

    static void init();

    void clear_ht(snort::HostTracker& ht);

    static unsigned inspector_id;
    RnaTracker serverht = nullptr;
    RnaTracker clientht = nullptr;

    std::mutex rna_mutex;

    RnaTracker get_server(const snort::SfIp&);
    RnaTracker get_client(const snort::SfIp&);
    RnaTracker get_tracker(const snort::Packet*, DiscoveryFilter&);

    void set_server(const RnaTracker& ht);
    void set_client(const RnaTracker& ht);

};

#endif
