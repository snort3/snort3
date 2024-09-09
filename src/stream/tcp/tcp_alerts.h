//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

// tcp_alerts.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 31, 2015

#ifndef TCP_ALERTS_H
#define TCP_ALERTS_H

#include <cstdint>

#include "protocols/packet.h"
#include "stream/stream.h"

struct StreamAlertInfo: snort::AlertInfo
{
    StreamAlertInfo(uint32_t gid_, uint32_t sid_, uint32_t seq_num_ = 0, uint32_t id_ = 0,
        uint32_t ts_ = 0) : snort::AlertInfo(gid_, sid_, id_, ts_), seq(seq_num_)
    { }

    uint32_t seq;
};

class TcpAlerts
{
public:
    TcpAlerts() = default;

    void clear()
    {
        xtradata_mask = 0;
        alerts.clear();
    }

    bool add_alert(uint32_t gid, uint32_t sid);
    bool check_alerted(uint32_t gid, uint32_t sid);
    int update_alert(uint32_t gid, uint32_t sid, uint32_t event_id, uint32_t event_second);
    void purge_alerts(snort::Flow* flow);
    void purge_alerts(snort::Packet& last_pdu, bool ips_enabled);

    void set_xtradata_mask(uint32_t mask)
    {
        xtradata_mask = mask;
    }

    uint32_t get_xtradata_mask() const
    {
        return xtradata_mask;
    }

private:

    uint32_t xtradata_mask = 0; // extra data available to log
    std::vector<StreamAlertInfo> alerts;

};

#endif
