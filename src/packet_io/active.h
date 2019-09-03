//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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

    struct Counts
    {
        PegCount injects;
    };

    enum ActiveStatus : uint8_t
    { AST_ALLOW, AST_CANT, AST_WOULD, AST_FORCE, AST_MAX };

    enum ActiveAction : uint8_t
    { ACT_PASS, ACT_HOLD, ACT_RETRY, ACT_DROP, ACT_BLOCK, ACT_RESET, ACT_MAX };

public:
    static void init(SnortConfig*);
    static bool thread_init(SnortConfig*);
    static void thread_term();

    static void set_enabled(bool on_off = true)
    { enabled = on_off; }

    static void suspend()
    { s_suspend = true; }

    static void resume()
    { s_suspend = false; }

    void send_reset(Packet*, EncodeFlags);
    void send_unreach(Packet*, snort::UnreachResponse);
    bool send_data(Packet*, EncodeFlags, const uint8_t* buf, uint32_t len);
    void inject_data(Packet*, EncodeFlags, const uint8_t* buf, uint32_t len);

    bool is_reset_candidate(const Packet*);
    bool is_unreachable_candidate(const Packet*);

    ActiveAction get_action() const
    { return active_action; }

    ActiveStatus get_status() const
    { return active_status; }

    void kill_session(Packet*, EncodeFlags = ENC_FLAG_FWD);

    bool can_block() const
    { return active_status == AST_ALLOW or active_status == AST_FORCE; }

    const char* get_action_string() const
    { return act_str[active_action][active_status]; }

    void drop_packet(const Packet*, bool force = false);
    void daq_drop_packet(const Packet*);
    bool retry_packet(const Packet*);
    bool hold_packet(const Packet*);

    void allow_session(Packet*);
    void block_session(Packet*, bool force = false);
    void reset_session(Packet*, bool force = false);

    void block_again()
    { active_action = ACT_BLOCK; }

    void reset_again()
    { active_action = ACT_RESET; }

    bool packet_was_dropped() const
    { return active_action >= ACT_DROP; }

    bool packet_would_be_dropped() const
    { return active_status == AST_WOULD; }

    bool packet_retry_requested() const
    { return active_action == ACT_RETRY; }

    bool session_was_blocked() const
    { return active_action >= ACT_BLOCK; }

    bool packet_force_dropped() const
    { return active_status == AST_FORCE; }

    bool is_packet_held() const
    { return active_action == ACT_HOLD; }

    void set_tunnel_bypass()
    { active_tunnel_bypass++; }

    void clear_tunnel_bypass()
    { active_tunnel_bypass--; }

    bool get_tunnel_bypass() const
    { return active_tunnel_bypass > 0; }

    void set_delayed_action(ActiveAction, bool force = false);
    void apply_delayed_action(Packet*);

    void reset();

private:
    static bool open(const char*);
    static void close();
    static int send_eth(DAQ_Msg_h, int, const uint8_t* buf, uint32_t len);
    static int send_ip(DAQ_Msg_h, int, const uint8_t* buf, uint32_t len);

    void update_status(const Packet*, bool force = false);
    void daq_update_status(const Packet*);

    void block_session(const Packet*, ActiveAction, bool force = false);

    void cant_drop();


private:
    static const char* act_str[ACT_MAX][AST_MAX];
    static bool enabled;
    static THREAD_LOCAL uint8_t s_attempts;
    static THREAD_LOCAL bool s_suspend;

    int active_tunnel_bypass;

    // these can't be pkt flags because we do the handling
    // of these flags following all processing and the drop
    // or response may have been produced by a pseudopacket.
    ActiveStatus active_status;
    ActiveAction active_action;
    ActiveAction delayed_active_action;
};

struct ActiveSuspendContext
{
    ActiveSuspendContext()
    { Active::suspend(); }

    ~ActiveSuspendContext()
    { Active::resume(); }
};

extern THREAD_LOCAL Active::Counts active_counts;
}
#endif

