//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

// tcp_module.h author Russ Combs <rucombs@cisco.com>

#ifndef TCP_MODULE_H
#define TCP_MODULE_H

#include "flow/session.h"
#include "framework/module.h"
#include "stream/tcp/tcp_stream_config.h"

#define GID_STREAM_TCP  129

#define STREAM_TCP_SYN_ON_EST                      1
#define STREAM_TCP_DATA_ON_SYN                     2
#define STREAM_TCP_DATA_ON_CLOSED                  3
#define STREAM_TCP_BAD_TIMESTAMP                   4
#define STREAM_TCP_BAD_SEGMENT                     5
#define STREAM_TCP_WINDOW_TOO_LARGE                6
#define STREAM_TCP_EXCESSIVE_TCP_OVERLAPS          7
#define STREAM_TCP_DATA_AFTER_RESET                8
#define STREAM_TCP_SESSION_HIJACKED_CLIENT         9
#define STREAM_TCP_SESSION_HIJACKED_SERVER        10
#define STREAM_TCP_DATA_WITHOUT_FLAGS             11
#define STREAM_TCP_SMALL_SEGMENT                  12
#define STREAM_TCP_4WAY_HANDSHAKE                 13
#define STREAM_TCP_NO_TIMESTAMP                   14
#define STREAM_TCP_BAD_RST                        15
#define STREAM_TCP_BAD_FIN                        16
#define STREAM_TCP_BAD_ACK                        17
#define STREAM_TCP_DATA_AFTER_RST_RCVD            18
#define STREAM_TCP_WINDOW_SLAM                    19
#define STREAM_TCP_NO_3WHS                        20
#define STREAM_TCP_MAX_EVENTS                     32

extern const PegInfo tcp_pegs[];

extern THREAD_LOCAL ProfileStats s5TcpPerfStats;
extern THREAD_LOCAL ProfileStats s5TcpNewSessPerfStats;
extern THREAD_LOCAL ProfileStats s5TcpStatePerfStats;
extern THREAD_LOCAL ProfileStats s5TcpDataPerfStats;
extern THREAD_LOCAL ProfileStats s5TcpInsertPerfStats;
extern THREAD_LOCAL ProfileStats s5TcpPAFPerfStats;
extern THREAD_LOCAL ProfileStats s5TcpFlushPerfStats;
extern THREAD_LOCAL ProfileStats s5TcpBuildPacketPerfStats;
extern THREAD_LOCAL ProfileStats streamSizePerfStats;

struct TcpStats
{
    SESSION_STATS;
    PegCount resyns;
    PegCount discards;
    PegCount events;
    PegCount ignored;
    PegCount no_pickups;
    PegCount sessions_on_syn;
    PegCount sessions_on_syn_ack;
    PegCount sessions_on_3way;
    PegCount sessions_on_data;
    PegCount segs_queued;
    PegCount segs_released;
    PegCount segs_split;
    PegCount segs_used;
    PegCount rebuilt_packets;   //iStreamFlushes
    PegCount rebuilt_buffers;
    PegCount rebuilt_bytes;     //total_rebuilt_bytes
    PegCount overlaps;
    PegCount gaps;
    PegCount exceeded_max_segs;
    PegCount exceeded_max_bytes;
    PegCount internalEvents;
    PegCount s5tcp1;
    PegCount s5tcp2;
    PegCount mem_in_use;
    PegCount sessions_initializing;
    PegCount sessions_established;
    PegCount sessions_closing;
    PegCount syns;
    PegCount syn_acks;
    PegCount resets;
    PegCount fins;
};

struct TcpStatTypes
{
    SESSION_STAT_TYPES;
    CountType resyns = CountType::SUM;
    CountType discards = CountType::SUM;
    CountType events = CountType::SUM;
    CountType ignored = CountType::SUM;
    CountType no_pickups = CountType::SUM;
    CountType sessions_on_syn = CountType::SUM;
    CountType sessions_on_syn_ack = CountType::SUM;
    CountType sessions_on_3way = CountType::SUM;
    CountType sessions_on_data = CountType::SUM;
    CountType segs_queued = CountType::SUM;
    CountType segs_released = CountType::SUM;
    CountType segs_split = CountType::SUM;
    CountType segs_used = CountType::SUM;
    CountType rebuilt_packets = CountType::SUM;
    CountType rebuilt_buffers = CountType::SUM;
    CountType rebuilt_bytes = CountType::SUM;
    CountType overlaps = CountType::SUM;
    CountType gaps = CountType::SUM;
    CountType exceeded_max_segs = CountType::SUM;
    CountType exceeded_max_bytes = CountType::SUM;
    CountType internalEvents = CountType::SUM;
    CountType s5tcp1 = CountType::SUM;
    CountType s5tcp2 = CountType::SUM;
    CountType mem_in_use = CountType::NOW;
    CountType sessions_initializing = CountType::NOW;
    CountType sessions_established = CountType::NOW;
    CountType sessions_closing = CountType::NOW;
    CountType syns = CountType::SUM;
    CountType syn_acks = CountType::SUM;
    CountType resets = CountType::SUM;
    CountType fins = CountType::SUM;

    TcpStatTypes() {}
};

extern THREAD_LOCAL struct TcpStats tcpStats;

inline void inc_tcp_discards()
{
    tcpStats.discards++;
}

//-------------------------------------------------------------------------
// stream_tcp module
//-------------------------------------------------------------------------

#define MOD_NAME "stream_tcp"
#define MOD_HELP "stream inspector for TCP flow tracking and stream normalization and reassembly"

struct SnortConfig;

class StreamTcpModule : public Module
{
public:
    StreamTcpModule();
    ~StreamTcpModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    const RuleMap* get_rules() const override;

    unsigned get_gid() const override
    {
        return GID_STREAM_TCP;
    }

    TcpStreamConfig* get_data();
    ProfileStats* get_profile(unsigned, const char*&, const char*&) const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    void sum_stats(bool) override;

private:
    TcpStreamConfig* config;
};

#endif

