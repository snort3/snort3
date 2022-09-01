//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
// dhcp_events.h author Sreeja Athirkandathil Narayanan <sathirka@cisco.com>

#ifndef DHCP_EVENTS_H
#define DHCP_EVENTS_H

#include <cstring>
#include "framework/data_bus.h"

#define DHCP_DATA_EVENT "dhcp_data_event"
#define DHCP_INFO_EVENT "dhcp_info_event"
#define DHCP_OP55_MAX_SIZE  64
#define DHCP_OP60_MAX_SIZE  64

namespace snort
{

class DHCPInfoEvent : public snort::DataEvent
{
public:
    DHCPInfoEvent(const snort::Packet* p, uint32_t ip_address, const uint8_t* eth,
        uint32_t subnet_mask, uint32_t lease_secs, uint32_t router) :
        pkt(p), ip_address(ip_address), subnet_mask(subnet_mask),
        lease_secs(lease_secs), router(router)
    {
        memcpy(eth_addr, eth, sizeof(eth_addr));
    }

    const snort::Packet* get_packet() const override
    { return pkt; }

    uint32_t get_ip_address() const
    { return ip_address; }

    const uint8_t* get_eth_addr() const
    { return eth_addr; }

    uint32_t get_subnet_mask() const
    { return subnet_mask; }

    uint32_t get_lease_secs() const
    { return lease_secs; }

    uint32_t get_router() const
    { return router; }

private:
    const snort::Packet* pkt;
    uint32_t ip_address;
    uint8_t eth_addr[6];
    uint32_t subnet_mask;
    uint32_t lease_secs;
    uint32_t router;
};

class DHCPDataEvent : public snort::DataEvent
{
public:
    DHCPDataEvent(const snort::Packet* p, unsigned op55_len, unsigned op60_len,
        const uint8_t* op55_val, const uint8_t* op60_val, const uint8_t* eth) : pkt(p),
        op55_len(op55_len), op60_len(op60_len)
    {
        memcpy(op55, op55_val, op55_len);
        if (op60_len)
            memcpy(op60, op60_val, op60_len);
        memcpy(eth_addr, eth, sizeof(eth_addr));
    }

    const snort::Packet* get_packet() const override
    { return pkt; }

    unsigned get_op55_len() const
    { return op55_len; }

    unsigned get_op60_len() const
    { return op60_len; }

    const uint8_t* get_op55() const
    { return op55; }

    const uint8_t* get_op60() const
    { return op60; }

    const uint8_t* get_eth_addr() const
    { return eth_addr; }

private:
    const snort::Packet* pkt;
    unsigned op55_len;
    unsigned op60_len;
    uint8_t op55[DHCP_OP55_MAX_SIZE] = {0};
    uint8_t op60[DHCP_OP60_MAX_SIZE] = {0};
    uint8_t eth_addr[6];
};

}

#endif // DHCP_EVENTS_H
