//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifndef SESSION_H
#define SESSION_H

// Session is an abstract base class for the various protocol subclasses.
// the subclasses do the actual work of tracking, reassembly, etc.

#include <cassert>
#include "stream/stream.h"

namespace snort
{
class Flow;
struct Packet;
struct SfIp;
class StreamSplitter;
}

class Session
{
public:
    virtual ~Session() = default;

    virtual bool setup(snort::Packet*) { return true; }
    virtual void update_direction(char /*dir*/, const snort::SfIp*, uint16_t /*port*/) { }
    virtual int process(snort::Packet*) { return 0; }

    virtual void restart(snort::Packet*) { }
    virtual void precheck(snort::Packet*) { }
    virtual void clear() = 0;
    virtual void cleanup(snort::Packet* = nullptr) { clear(); }

    virtual bool add_alert(snort::Packet*, uint32_t /*gid*/, uint32_t /*sid*/) { return false; }
    virtual bool check_alerted(snort::Packet*, uint32_t /*gid*/, uint32_t /*sid*/) { return false; }

    virtual int update_alert(
        snort::Packet*, uint32_t /*gid*/, uint32_t /*sid*/,
        uint32_t /*event_id*/, uint32_t /*event_second*/) { return 0; }

    virtual void flush_client(snort::Packet*) { }
    virtual void flush_server(snort::Packet*) { }
    virtual void flush_talker(snort::Packet*, bool /*final_flush */ = false) { }
    virtual void flush_listener(snort::Packet*, bool /*final_flush */ = false) { }

    virtual void set_splitter(bool /*c2s*/, snort::StreamSplitter*) { assert(false); }
    virtual snort::StreamSplitter* get_splitter(bool /*c2s*/) { return nullptr; }

    virtual void set_extra_data(snort::Packet*, uint32_t /*flag*/) { }

    virtual bool is_sequenced(uint8_t /*dir*/) { return true; }
    virtual bool are_packets_missing(uint8_t /*dir*/) { return true; }

    virtual uint8_t get_reassembly_direction() { return SSN_DIR_NONE; }
    virtual uint8_t missing_in_reassembled(uint8_t /*dir*/) { return SSN_MISSING_NONE; }

protected:
    Session(snort::Flow* f) { flow = f; }

public:
    snort::Flow* flow;  // FIXIT-L use reference?
};

/* These should be tracked by all Session subclasses. Add to top of peg list.
 * Having these predefined stats improves consistency and provides convenience.
 */
#define SESSION_PEGS(module) \
    { CountType::SUM, "sessions", "total " module " sessions" }, \
    { CountType::MAX, "max", "max " module " sessions" }, \
    { CountType::SUM, "created", module " session trackers created" }, \
    { CountType::SUM, "released", module " session trackers released" }, \
    { CountType::SUM, "timeouts", module " session timeouts" }, \
    { CountType::SUM, "prunes", module " session prunes" }

// See above. Add to end of stats array.
#define SESSION_STATS \
    PegCount sessions; \
    PegCount max; \
    PegCount created; \
    PegCount released; \
    PegCount timeouts; \
    PegCount prunes

// Do not change the semantics of max. Max = the highest seen during the perf interval.
// To obtain max over the entire run, determine the maximum of reported max pegs.
#define SESSION_STATS_ADD(stats) \
    { \
        (stats).sessions++; \
        (stats).created++; \
        if ( (stats).max < (stats).sessions ) \
            (stats).max = (stats).sessions; \
    }

#endif

