//--------------------------------------------------------------------------
// Copyright (C) 2018-2023 Cisco and/or its affiliates. All rights reserved.
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

// appid_debug.h author Mike Stepanek <mstepane@cisco.com>
// Created on: March 6, 2018

#ifndef APPID_DEBUG_H
#define APPID_DEBUG_H

#include <cstring>

#include <daq_common.h>

#include "protocols/ipv6.h"
#include "protocols/protocol_ids.h"
#include "main/thread.h"
#include "sfip/sf_ip.h"

class AppIdSession;
namespace snort
{
    class Flow;
}

// %s %u -> %s %u %u AS=%u ID=%u [GR=%hd-%hd]
// IPv6 Port -> IPv6 Port Proto AS=ASNum ID=InstanceNum [GR=SrcGroupNum-DstGroupNum]
#define APPID_DEBUG_SESSION_ID_SIZE ((39+1+5+1+2+1+39+1+5+1+3+1+2+1+10+1+2+1+10+32)+1)

struct AppIdDebugSessionConstraints
{
    snort::SfIp sip;
    bool sip_flag = false;
    snort::SfIp dip;
    bool dip_flag = false;
    uint16_t sport;
    uint16_t dport;
    IpProtocol protocol = IpProtocol::PROTO_NOT_SET;
    bool proto_match(IpProtocol proto) const
    {
        return (protocol == IpProtocol::PROTO_NOT_SET or protocol == proto);
    }
    bool port_match(uint16_t p1, uint16_t p2) const
    {
        return (!sport or sport == p1) and (!dport or dport == p2);
    }
    bool ip_match(const uint32_t* ip1, const uint32_t* ip2) const
    {
        return
            ((!sip_flag or !memcmp(sip.get_ip6_ptr(), ip1, sizeof(snort::ip::snort_in6_addr))) and
             (!dip_flag or !memcmp(dip.get_ip6_ptr(), ip2, sizeof(snort::ip::snort_in6_addr))));
    }
};

class AppIdDebug
{
public:
    AppIdDebug() = default;

    void activate(const uint32_t* ip1, const uint32_t* ip2, uint16_t port1, uint16_t port2,
        IpProtocol protocol, const int version, uint32_t address_space_id,
        const AppIdSession* session, bool log_all_sessions, int16_t group1 = DAQ_PKTHDR_UNKNOWN,
        int16_t group2 = DAQ_PKTHDR_UNKNOWN, bool inter_group_flow = false);
    void activate(const snort::Flow *flow, const AppIdSession* session, bool log_all_sessions);
    void set_constraints(const char *desc, const AppIdDebugSessionConstraints* constraints);

    bool is_enabled() { return enabled; }
    void set_enabled(bool enable) { enabled = enable; }

    bool is_active() { return active; }
    void deactivate() { active = false; }

    const char* get_debug_session()
    {
        return debug_session;
    }

private:
    bool enabled = false;
    bool active = false;
    AppIdDebugSessionConstraints info = { };
    char debug_session[APPID_DEBUG_SESSION_ID_SIZE];
};

extern THREAD_LOCAL AppIdDebug* appidDebug;

#endif
