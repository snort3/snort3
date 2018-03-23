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

void AppIdDebug::activate(const uint32_t* ip1, const uint32_t* ip2, uint16_t port1, uint16_t port2, IpProtocol protocol,
                          uint16_t address_space_id, const AppIdSession* session, bool log_all_sessions)
{
    if ((log_all_sessions) ||
        (enabled && (info.protocol == IpProtocol::PROTO_NOT_SET || info.protocol == protocol) &&
            (((!info.sport || info.sport == port1) && (!info.dport || info.dport == port2) &&
              (!info.sip_flag || memcmp(&info.sip, ip1, sizeof(info.sip)) == 0) &&
              (!info.dip_flag || memcmp(&info.dip, ip2, sizeof(info.dip)) == 0)) ||
             ((!info.sport || info.sport == port2) && (!info.dport || info.dport == port1) &&
              (!info.sip_flag || memcmp(&info.sip, ip2, sizeof(info.sip)) == 0) &&
              (!info.dip_flag || memcmp(&info.dip, ip1, sizeof(info.dip)) == 0)))))
    {
        active = true;
        int af;
        const struct in6_addr* sip;
        const struct in6_addr* dip;
        unsigned offset;
        uint16_t sport = 0;
        uint16_t dport = 0;
        char sipstr[INET6_ADDRSTRLEN];
        char dipstr[INET6_ADDRSTRLEN];

        if (!session)
        {
            sip = (const struct in6_addr*)ip1;
            dip = (const struct in6_addr*)ip2;
            sport = port1;
            dport = port2;
        }
        else if (session->common.initiator_port)
        {
            if (session->common.initiator_port == port1)
            {
                sip = (const struct in6_addr*)ip1;
                dip = (const struct in6_addr*)ip2;
                sport = port1;
                dport = port2;
            }
            else
            {
                sip = (const struct in6_addr*)ip2;
                dip = (const struct in6_addr*)ip1;
                sport = port2;
                dport = port1;
            }
        }
        else if (memcmp(session->common.initiator_ip.get_ip6_ptr(), ip1, sizeof(struct in6_addr)) == 0)
        {
            sip = (const struct in6_addr*)ip1;
            dip = (const struct in6_addr*)ip2;
            sport = port1;
            dport = port2;
        }
        else
        {
            sip = (const struct in6_addr*)ip2;
            dip = (const struct in6_addr*)ip1;
            sport = port2;
            dport = port1;
        }
        sipstr[0] = 0;
        if (sip->s6_addr32[0] || sip->s6_addr32[1] || sip->s6_addr16[4] || (sip->s6_addr16[5] && sip->s6_addr16[5] != 0xFFFF))
        {
            af = AF_INET6;
            offset = 0;
        }
        else
        {
            af = AF_INET;
            offset = 12;
        }
        inet_ntop(af, &sip->s6_addr[offset], sipstr, sizeof(sipstr));
        dipstr[0] = 0;
        if (dip->s6_addr32[0] || dip->s6_addr32[1] || dip->s6_addr16[4] || (dip->s6_addr16[5] && dip->s6_addr16[5] != 0xFFFF))
        {
            af = AF_INET6;
            offset = 0;
        }
        else
        {
            af = AF_INET;
            offset = 12;
        }
        inet_ntop(af, &dip->s6_addr[offset], dipstr, sizeof(dipstr));

        snprintf(debug_session, sizeof(debug_session), "%s %hu -> %s %hu %hhu AS=%hu ID=%u",
                 sipstr, sport, dipstr, dport, static_cast<uint8_t>(protocol), address_space_id, instance_id);
    }
    else
        active = false;
}

void AppIdDebug::activate(const Flow *flow, const AppIdSession* session, bool log_all_sessions)
{
    if (flow == nullptr)
    {
        active = false;
        return;
    }
    const FlowKey* key = flow->key;
    activate(key->ip_l, key->ip_h, key->port_l, key->port_h, (IpProtocol)(key->ip_protocol),
             key->addressSpaceId, session, log_all_sessions);
}

void AppIdDebug::set_constraints(const char *desc, const AppIdDebugSessionConstraints* constraints)
{
    if (constraints)
    {
        int saf;
        int daf;
        char sipstr[INET6_ADDRSTRLEN];
        char dipstr[INET6_ADDRSTRLEN];

        memcpy(&info, constraints, sizeof(info));
        if (!info.sip.s6_addr32[0] && !info.sip.s6_addr32[1] && !info.sip.s6_addr16[4] &&
            info.sip.s6_addr16[5] == 0xFFFF)
        {
            saf = AF_INET;
        }
        else
            saf = AF_INET6;
        if (!info.dip.s6_addr32[0] && !info.dip.s6_addr32[1] && !info.dip.s6_addr16[4] &&
            info.dip.s6_addr16[5] == 0xFFFF)
        {
            daf = AF_INET;
        }
        else
            daf = AF_INET6;
        sipstr[0] = 0;
        inet_ntop(saf, saf == AF_INET ? &info.sip.s6_addr32[3] : info.sip.s6_addr32, sipstr, sizeof(sipstr));
        dipstr[0] = 0;
        inet_ntop(daf, daf == AF_INET ? &info.dip.s6_addr32[3] : info.dip.s6_addr32, dipstr, sizeof(dipstr));
        LogMessage("Debugging %s with %s-%hu and %s-%hu %hhu\n", desc,
                    sipstr, info.sport, dipstr, info.dport, static_cast<uint8_t>(info.protocol));

        enabled = true;
    }
    else
    {
        LogMessage("Debugging %s disabled\n", desc);
        enabled = false;
    }

}
