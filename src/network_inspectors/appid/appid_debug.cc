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

// appid_debug.cc author Mike Stepanek <mstepane@cisco.com>
// Created on: March 6, 2018

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "appid_debug.h"

#include "flow/flow_key.h"
#include "log/messages.h"

#include "appid_config.h"
#include "appid_session.h"

using namespace snort;
THREAD_LOCAL AppIdDebug* appidDebug = nullptr;

void AppIdDebug::activate(const uint32_t* ip1, const uint32_t* ip2, uint16_t port1,
    uint16_t port2, IpProtocol protocol, const int version, uint16_t address_space_id,
    const AppIdSession* session, bool log_all_sessions)
{
    if (!( log_all_sessions or
           ( info.proto_match(protocol) and
             ( (info.port_match(port1, port2) and info.ip_match(ip1, ip2)) or
               (info.port_match(port2, port1) and info.ip_match(ip2, ip1)) ) ) ))
    {
        active = false;
        return;
    }
    active = true;
    int af = (version == 6)? AF_INET6 : AF_INET;
    const ip::snort_in6_addr* sip;
    const ip::snort_in6_addr* dip;
    uint16_t sport = 0;
    uint16_t dport = 0;
    char sipstr[INET6_ADDRSTRLEN];
    char dipstr[INET6_ADDRSTRLEN];

    if (!session)
    {
        sip = (const ip::snort_in6_addr*)ip1;
        dip = (const ip::snort_in6_addr*)ip2;
        sport = port1;
        dport = port2;
    }
    else if (session->common.initiator_port)
    {
        if (session->common.initiator_port == port1)
        {
            sip = (const ip::snort_in6_addr*)ip1;
            dip = (const ip::snort_in6_addr*)ip2;
            sport = port1;
            dport = port2;
        }
        else
        {
            sip = (const ip::snort_in6_addr*)ip2;
            dip = (const ip::snort_in6_addr*)ip1;
            sport = port2;
            dport = port1;
        }
    }
    else if (memcmp(session->common.initiator_ip.get_ip6_ptr(),
                ip1, sizeof(ip::snort_in6_addr)) == 0)
    {
        sip = (const ip::snort_in6_addr*)ip1;
        dip = (const ip::snort_in6_addr*)ip2;
        sport = port1;
        dport = port2;
    }
    else
    {
        sip = (const ip::snort_in6_addr*)ip2;
        dip = (const ip::snort_in6_addr*)ip1;
        sport = port2;
        dport = port1;
    }
    snort_inet_ntop(af, &sip->u6_addr32[(af == AF_INET)? 3 : 0], sipstr, sizeof(sipstr));
    snort_inet_ntop(af, &dip->u6_addr32[(af == AF_INET)? 3 : 0], dipstr, sizeof(dipstr));

    snprintf(debug_session, sizeof(debug_session), "%s %hu -> %s %hu %hhu AS=%hu ID=%u",
        sipstr, sport, dipstr, dport, static_cast<uint8_t>(protocol),
        address_space_id, get_instance_id());
}

void AppIdDebug::activate(const Flow *flow, const AppIdSession* session, bool log_all_sessions)
{
    if (flow == nullptr)
    {
        active = false;
        return;
    }
    const FlowKey* key = flow->key;

    // FIXIT-H FlowKey does not yet support different address families for src and dst IPs
    // (e.g., IPv4 src and IPv6 dst, or vice-versa). Once it is supported, we need to pass
    // two key->version here to create the proper debug_session string.
    activate(key->ip_l, key->ip_h, key->port_l, key->port_h, (IpProtocol)(key->ip_protocol),
        key->version, key->addressSpaceId, session, log_all_sessions);
}

void AppIdDebug::set_constraints(const char *desc,
        const AppIdDebugSessionConstraints* constraints)
{
    if (constraints)
    {
        char sipstr[INET6_ADDRSTRLEN];
        char dipstr[INET6_ADDRSTRLEN];

        info.set(*constraints);
        info.sip.ntop(sipstr, sizeof(sipstr));
        info.dip.ntop(dipstr, sizeof(dipstr));
        LogMessage("Debugging %s with %s-%hu and %s-%hu %hhu\n", desc,
            sipstr, info.sport, dipstr, info.dport, static_cast<uint8_t>(info.protocol));

        enabled = true;
    }
    else
    {
        LogMessage("Debugging %s disabled\n", desc);
        enabled = false;
        active = false;
    }

}
