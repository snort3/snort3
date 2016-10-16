//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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
// user_session.h author Russ Combs <rucombs@cisco.com>

#ifndef USER_SESSION_H
#define USER_SESSION_H

#include <list>

#include "flow/session.h"
#include "stream/paf.h"

struct UserSegment
{
    static UserSegment* init(const uint8_t*, unsigned);
    static void term(UserSegment*);

    unsigned avail();
    void copy(const uint8_t*, unsigned);
    void shift(unsigned);

    unsigned get_len();
    uint8_t* get_data();

    bool unused();
    void use(unsigned);
    void reset();

    unsigned get_unused_len();
    uint8_t* get_unused_data();

private:
    unsigned len;
    unsigned offset;
    unsigned used;
    uint8_t data[1];
};

struct UserTracker
{
    UserTracker();
    ~UserTracker();

    void init();
    void term();

    void process(Packet*);
    void add_data(Packet*);
    int scan(Packet*, uint32_t&);
    void flush(struct Packet*, unsigned, uint32_t);
    void detect(const struct Packet*, const struct StreamBuffer&, uint32_t, Packet* up);

    std::list<UserSegment*> seg_list;
    StreamSplitter* splitter;
    PAF_State paf_state;
    unsigned total;
};

class UserSession : public Session
{
public:
    UserSession(Flow*);
    ~UserSession();

    bool setup(Packet*) override;
    void clear() override;

    int process(Packet*) override;

    void set_splitter(bool c2s, StreamSplitter*) override;
    StreamSplitter* get_splitter(bool c2s) override;
    void restart(Packet*) override;

    bool is_sequenced(uint8_t /*dir*/) override
    { return true; }

    bool are_packets_missing(uint8_t /*dir*/) override
    { return false; }

    uint8_t missing_in_reassembled(uint8_t /*dir*/) override
    { return SSN_MISSING_NONE; }

private:
    void start(Packet*, Flow*);
    void update(Packet*, Flow*);
    void end(Packet*, Flow*);

    void update_direction(char dir, const SfIp*, uint16_t port) override;

    bool add_alert(Packet*, uint32_t gid, uint32_t sid) override;
    bool check_alerted(Packet*, uint32_t gid, uint32_t sid) override;

    int update_alert(
        Packet*, uint32_t gid, uint32_t sid, uint32_t event_id, uint32_t event_second) override;

    void flush_client(Packet*) override { }
    void flush_server(Packet*) override { }
    void flush_talker(Packet*, bool /*final_flush */ = false) override { }
    void flush_listener(Packet*, bool /*final_flush */ = false) override { }

    void set_extra_data(Packet*, uint32_t /* flag */) override { }
    void clear_extra_data(Packet*, uint32_t /* flag */) override { }

    uint8_t get_reassembly_direction() override;

public:
    UserTracker client;
    UserTracker server;
};

#endif

