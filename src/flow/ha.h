//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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
// ha.h author Ed Borgoyn <eborgoyn@cisco.com>

#ifndef HA_H
#define HA_H

#include "flow.h"
#include "main/snort_types.h"
#include "packet_io/sfdaq.h"
#include "side_channel/side_channel.h"

//-------------------------------------------------------------------------

typedef uint16_t FlowHAClientHandle;

class FlowHAState
{
public:
    static const uint8_t CRITICAL = 0x20;
    static const uint8_t MAJOR = 0x10;

    static const uint8_t NEW = 0x01;
    static const uint8_t MODIFIED = 0x02;
    static const uint8_t DELETED = 0x04;
    static const uint8_t STANDBY = 0x08;

    void set_pending(FlowHAClientHandle);
    bool check_and_clear_pending(FlowHAClientHandle);
    void set_state(uint8_t state);
    void set_state(uint8_t state, uint8_t priority);
    void clr_state(uint8_t state);
    void clr_state(uint8_t state, uint8_t priority);
    bool critical();
    bool major();
    static void config_lifetime(timeval);
    bool old_enough();
    void set_next_update();
    void initialize_update_time();

private:
    FlowHAState();

    static const uint8_t initial_state = 0x00;
    static const uint16_t none_pending = 0x0000;
    static const uint8_t priority_mask = 0x30;
    static const uint8_t status_mask = 0x0f;

    static struct timeval min_session_lifetime;
    uint8_t state;
    uint16_t pending;
    struct timeval next_update;
};

class FlowHAClient
{
public:
private:
};

class Flow;

class HighAvailability
{
public:
    HighAvailability(PortBitSet*,bool);
    ~HighAvailability();

    void process(Flow*, const DAQ_PktHdr_t*);

private:
    void receive_handler(SCMessage*);
    SideChannel* sc = nullptr;
    bool enabled = false;
};

class HighAvailabilityManager
{
public:
    static void pre_config_init();
    static bool instantiate(PortBitSet*,bool);
    static void thread_init();
    static void thread_term();
    static bool active();
    static void process(Flow*, const DAQ_PktHdr_t*);
private:
    HighAvailabilityManager() = delete;
    static bool use_daq_channel;
    static PortBitSet* ports;
};
#endif

