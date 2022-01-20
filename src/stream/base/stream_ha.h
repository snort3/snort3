//--------------------------------------------------------------------------
// Copyright (C) 2015-2022 Cisco and/or its affiliates. All rights reserved.
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
// stream_ha.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef STREAM_HA_H
#define STREAM_HA_H

#include "flow/flow.h"
#include "flow/ha.h"

class __attribute__((__packed__)) SessionHAContent
{
public:
    snort::LwState ssn_state;
    snort::Flow::FlowState flow_state;
    uint8_t flags;
    static constexpr uint8_t FLAG_LOW = 0x01; // client address / port is low in key
    static constexpr uint8_t FLAG_IP6 = 0x02; // key addresses are ip6
};

class StreamHAClient : public snort::FlowHAClient
{
public:
    StreamHAClient() : FlowHAClient(sizeof(SessionHAContent), true) { }
    bool consume(snort::Flow*&, const snort::FlowKey*, snort::HAMessage&, uint8_t size) override;
    bool produce(snort::Flow&, snort::HAMessage&) override;
    bool is_update_required(snort::Flow*) override;
};

class ProtocolHA
{
public:
    ProtocolHA(PktType);
    virtual ~ProtocolHA();
    virtual snort::Flow* create_session(const snort::FlowKey*) { return nullptr; }
    virtual void deactivate_session(snort::Flow*) { }
    virtual void process_deletion(snort::Flow&);
};

class StreamHAManager
{
public:
    static void tinit();
    static void tterm();

    static THREAD_LOCAL StreamHAClient* ha_client;
};
#endif

