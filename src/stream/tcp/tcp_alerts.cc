//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// tcp_alerts.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Nov 7, 2023

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cassert>

#include "tcp_alerts.h"

#include "detection/context_switcher.h"

#include "tcp_session.h"

using namespace snort;

static void purge_alerts_callback_ackd(IpsContext *c)
{
    TcpSession *session = (TcpSession*) c->packet->flow->session;

    if (c->packet->is_from_server())
        session->client.tcp_alerts.purge_alerts(c->packet->flow);
    else
        session->server.tcp_alerts.purge_alerts(c->packet->flow);
}

static void purge_alerts_callback_ips(IpsContext *c)
{
    TcpSession *session = (TcpSession*) c->packet->flow->session;

    if (c->packet->is_from_server())
        session->server.tcp_alerts.purge_alerts(c->packet->flow);
    else
        session->client.tcp_alerts.purge_alerts(c->packet->flow);
}

bool TcpAlerts::add_alert(uint32_t gid, uint32_t sid)
{
    assert(
        alerts.size()
            <= (uint32_t )(get_ips_policy()->rules_loaded + get_ips_policy()->rules_shared));

    if (!this->check_alerted(gid, sid))
        alerts.emplace_back(gid, sid);

    return true;
}

bool TcpAlerts::check_alerted(uint32_t gid, uint32_t sid)
{
    return std::any_of(alerts.cbegin(), alerts.cend(), [gid, sid](const StreamAlertInfo &alert)
    {   return alert.gid == gid && alert.sid == sid;});
}

int TcpAlerts::update_alert(uint32_t gid, uint32_t sid, uint32_t event_id, uint32_t event_second)
{
    // FIXIT-M comparison of seq_num is wrong, compare value is always 0, should be seq_num of wire packet
    uint32_t seq_num = 0;

    auto it = std::find_if(alerts.begin(), alerts.end(),
        [gid, sid, seq_num](const StreamAlertInfo &alert)
        {   return alert.gid == gid && alert.sid == sid && SEQ_EQ(alert.seq, seq_num);});
    if (it != alerts.end())
    {
        (*it).event_id = event_id;
        (*it).event_second = event_second;
        return 0;
    }

    return -1;
}

void TcpAlerts::purge_alerts(Flow* flow)
{
    for (auto &alert : alerts)
        Stream::log_extra_data(flow, xtradata_mask, alert);

    if (!flow->is_suspended())
        alerts.clear();
}

void TcpAlerts::purge_alerts(Packet& last_pdu, bool ips_enabled)
{
    if ( ips_enabled )
        last_pdu.context->register_post_callback(purge_alerts_callback_ips);
    else
        last_pdu.context->register_post_callback(purge_alerts_callback_ackd);
}

