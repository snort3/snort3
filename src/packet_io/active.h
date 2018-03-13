//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// active.h author Russ Combs <rcombs@sourcefire.com>

#ifndef ACTIVE_H
#define ACTIVE_H

// manages packet processing verdicts returned to the DAQ.  action (what to
// do) is separate from status (whether we can actually do it or not).

#include "protocols/packet_manager.h"

namespace snort
{
struct Packet;
struct SnortConfig;

class SO_PUBLIC Active
{
public:
    enum ActiveStatus
    { AST_ALLOW, AST_CANT, AST_WOULD, AST_FORCE, AST_MAX };

    enum ActiveAction
    { ACT_PASS, ACT_DROP, ACT_BLOCK, ACT_RESET, ACT_RETRY, ACT_MAX };

public:
    static bool init(SnortConfig*);
    static void term();

    static void reset()
    {
        active_status = AST_ALLOW;
        active_action = ACT_PASS;
        active_tunnel_bypass = 0;
        delayed_active_action = ACT_PASS;
    }

    static void kill_session(Packet*, EncodeFlags = ENC_FLAG_FWD);

    static void send_reset(Packet*, EncodeFlags);
    static void send_unreach(Packet*, snort::UnreachResponse);
    static bool send_data(Packet*, EncodeFlags, const uint8_t* buf, uint32_t len);
    static void inject_data(Packet*, EncodeFlags, const uint8_t* buf, uint32_t len);

    static bool is_reset_candidate(const Packet*);
    static bool is_unreachable_candidate(const Packet*);

    static bool is_enabled();
    static void set_enabled(bool = true);

    static void suspend();
    static void resume();
    static bool suspended();

    static ActiveAction get_action();
    static ActiveStatus get_status();

    static bool can_block();

    static const char* get_action_string();

    static void drop_packet(const Packet*, bool force = false);
    static void daq_drop_packet(const Packet*);
    static bool daq_retry_packet(const Packet*);

    static void allow_session(Packet*);

    static void block_session(Packet*, bool force = false);
    static void reset_session(Packet*, bool force = false);

    static void block_again();
    static void reset_again();

    static bool packet_was_dropped();
    static bool packet_retry_requested();
    static bool session_was_blocked();
    static bool packet_would_be_dropped();
    static bool packet_force_dropped();

    static void set_tunnel_bypass();
    static void clear_tunnel_bypass();
    static bool get_tunnel_bypass();

    static uint64_t get_injects();

    static void set_delayed_action(ActiveAction, bool force = false);
    static void apply_delayed_action(Packet*);

private:
    static bool open(const char*);
    static void close();

    static int send_eth(
        const DAQ_PktHdr_t*, int, const uint8_t* buf, uint32_t len);

    static int send_ip(
        const DAQ_PktHdr_t*, int, const uint8_t* buf, uint32_t len);

    static void update_status(const Packet*, bool force = false);
    static void daq_update_status(const Packet*);

    static void block_session(const Packet*, ActiveAction, bool force = false);

    static void cant_drop();

private:
    static THREAD_LOCAL ActiveStatus active_status;
    static THREAD_LOCAL ActiveAction active_action;
    static THREAD_LOCAL ActiveAction delayed_active_action;

    static THREAD_LOCAL int active_tunnel_bypass;
    static THREAD_LOCAL bool active_suspend;

    static THREAD_LOCAL uint8_t s_attempts;
    static THREAD_LOCAL uint64_t s_injects;

    static bool s_enabled;
};

struct ActiveSuspendContext
{
    ActiveSuspendContext() { Active::suspend(); }
    ~ActiveSuspendContext() { Active::resume(); }
};
}
#endif

