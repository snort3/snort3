//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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

// cppcheck-suppress noConstructor
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
    unsigned size;
    uint8_t data[1];
};

struct UserTracker
{
    UserTracker();
    ~UserTracker();

    void init();
    void term();

    void process(snort::Packet*);
    void add_data(snort::Packet*);
    int scan(snort::Packet*, uint32_t&);
    void flush(struct snort::Packet*, unsigned, uint32_t);
    void detect(const struct snort::Packet*, const struct snort::StreamBuffer&, uint32_t, snort::Packet* up);

    std::list<UserSegment*> seg_list;
    snort::StreamSplitter* splitter;
    PAF_State paf_state = {};
    unsigned total;
};

class UserSession : public Session
{
public:
    UserSession(snort::Flow*);
    ~UserSession() override;

    bool setup(snort::Packet*) override;
    void clear() override;

    int process(snort::Packet*) override;

    void set_splitter(bool c2s, snort::StreamSplitter*) override;
    snort::StreamSplitter* get_splitter(bool c2s) override;
    void restart(snort::Packet*) override;

private:
    void start(snort::Packet*, snort::Flow*);
    void update(snort::Packet*, snort::Flow*);
    void end(snort::Packet*, snort::Flow*);

    bool add_alert(snort::Packet*, uint32_t gid, uint32_t sid) override;
    bool check_alerted(snort::Packet*, uint32_t gid, uint32_t sid) override;

    int update_alert(
        snort::Packet*, uint32_t gid, uint32_t sid, uint32_t event_id, uint32_t event_second) override;

public:
    UserTracker client;
    UserTracker server;
};

#endif

