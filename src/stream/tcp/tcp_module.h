//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

extern THREAD_LOCAL snort::ProfileStats s5TcpPerfStats;
extern THREAD_LOCAL snort::ProfileStats s5TcpNewSessPerfStats;
extern THREAD_LOCAL snort::ProfileStats s5TcpStatePerfStats;
extern THREAD_LOCAL snort::ProfileStats s5TcpDataPerfStats;
extern THREAD_LOCAL snort::ProfileStats s5TcpInsertPerfStats;
extern THREAD_LOCAL snort::ProfileStats s5TcpPAFPerfStats;
extern THREAD_LOCAL snort::ProfileStats s5TcpFlushPerfStats;
extern THREAD_LOCAL snort::ProfileStats s5TcpBuildPacketPerfStats;
extern THREAD_LOCAL snort::ProfileStats streamSizePerfStats;

struct TcpStats
{
    SESSION_STATS;
    PegCount instantiated;
    PegCount setups;
    PegCount restarts;
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
    PegCount client_cleanups;
    PegCount server_cleanups;
    PegCount mem_in_use;
    PegCount sessions_initializing;
    PegCount sessions_established;
    PegCount sessions_closing;
    PegCount syns;
    PegCount syn_acks;
    PegCount resets;
    PegCount fins;
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

namespace snort
{
struct SnortConfig;
}

class StreamTcpModule : public snort::Module
{
public:
    StreamTcpModule();

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const snort::RuleMap* get_rules() const override;

    unsigned get_gid() const override
    { return GID_STREAM_TCP; }

    TcpStreamConfig* get_data();
    snort::ProfileStats* get_profile(unsigned, const char*&, const char*&) const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    Usage get_usage() const override
    { return INSPECT; }

private:
    TcpStreamConfig* config;
};

#endif

