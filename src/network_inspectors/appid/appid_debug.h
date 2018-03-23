//--------------------------------------------------------------------------
// Copyright (C) 2018-2018 Cisco and/or its affiliates. All rights reserved.
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

#include <netinet/in.h>

#include "protocols/protocol_ids.h"
#include "main/thread.h"

class AppIdSession;
namespace snort
{
    class Flow;
}

// %s %u -> %s %u %u AS=%u ID=%u
// IPv6 Port -> IPv6 Port Proto AS=ASNum ID=InstanceNum
#define APPID_DEBUG_SESSION_ID_SIZE ((39+1+5+1+2+1+39+1+5+1+3+1+2+1+10+1+2+1+10)+1)

struct AppIdDebugSessionConstraints
{
    struct in6_addr sip;
    int sip_flag;
    struct in6_addr dip;
    int dip_flag;
    uint16_t sport;
    uint16_t dport;
    IpProtocol protocol = IpProtocol::PROTO_NOT_SET;
};

class AppIdDebug
{
public:
    AppIdDebug(unsigned instance_id) : instance_id(instance_id) { }

    void activate(const uint32_t* ip1, const uint32_t* ip2, uint16_t port1, uint16_t port2, IpProtocol protocol,
                  uint16_t address_space_id, const AppIdSession* session, bool log_all_sessions);
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
    unsigned instance_id;
    char debug_session[APPID_DEBUG_SESSION_ID_SIZE];
};

extern THREAD_LOCAL AppIdDebug* appidDebug;

#endif
