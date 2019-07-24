//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

#ifndef RNA_PND_H
#define RNA_PND_H

#include "protocols/eth.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

namespace snort
{
struct Packet;
}

class RnaPnd
{
public:
    void analyze_flow_icmp(const snort::Packet* p);
    void analyze_flow_ip(const snort::Packet* p);
    void analyze_flow_non_ip(const snort::Packet* p);
    void analyze_flow_tcp(const snort::Packet* p, bool is_midstream);
    void analyze_flow_udp(const snort::Packet* p);

private:
    // General rna utilities not associated with flow
    void discover_network_icmp(const snort::Packet* p);
    void discover_network_ip(const snort::Packet* p);
    void discover_network_non_ip(const snort::Packet* p);
    void discover_network_tcp(const snort::Packet* p);
    void discover_network_udp(const snort::Packet* p);
};

#endif
