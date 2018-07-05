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

// tcp_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_module.h"

#include "main/snort_config.h"
#include "profiler/profiler_defs.h"

using namespace snort;
using namespace std;

//-------------------------------------------------------------------------
// stream_tcp module
//-------------------------------------------------------------------------

THREAD_LOCAL ProfileStats s5TcpPerfStats;
THREAD_LOCAL ProfileStats s5TcpNewSessPerfStats;
THREAD_LOCAL ProfileStats s5TcpStatePerfStats;
THREAD_LOCAL ProfileStats s5TcpDataPerfStats;
THREAD_LOCAL ProfileStats s5TcpInsertPerfStats;
THREAD_LOCAL ProfileStats s5TcpPAFPerfStats;
THREAD_LOCAL ProfileStats s5TcpFlushPerfStats;
THREAD_LOCAL ProfileStats s5TcpBuildPacketPerfStats;

const PegInfo tcp_pegs[] =
{
    SESSION_PEGS("tcp"),
    { CountType::SUM, "instantiated", "new sessions instantiated" },
    { CountType::SUM, "setups", "session initializations" },
    { CountType::SUM, "restarts", "sessions restarted" },
    { CountType::SUM, "resyns", "SYN received on established session" },
    { CountType::SUM, "discards", "tcp packets discarded" },
    { CountType::SUM, "events", "events generated" },
    { CountType::SUM, "ignored", "tcp packets ignored" },
    { CountType::SUM, "untracked", "tcp packets not tracked" },
    { CountType::SUM, "syn_trackers", "tcp session tracking started on syn" },
    { CountType::SUM, "syn_ack_trackers", "tcp session tracking started on syn-ack" },
    { CountType::SUM, "three_way_trackers", "tcp session tracking started on ack" },
    { CountType::SUM, "data_trackers", "tcp session tracking started on data" },
    { CountType::SUM, "segs_queued", "total segments queued" },
    { CountType::SUM, "segs_released", "total segments released" },
    { CountType::SUM, "segs_split", "tcp segments split when reassembling PDUs" },
    { CountType::SUM, "segs_used", "queued tcp segments applied to reassembled PDUs" },
    { CountType::SUM, "rebuilt_packets", "total reassembled PDUs" },
    { CountType::SUM, "rebuilt_buffers", "rebuilt PDU sections" },
    { CountType::SUM, "rebuilt_bytes", "total rebuilt bytes" },
    { CountType::SUM, "overlaps", "overlapping segments queued" },
    { CountType::SUM, "gaps", "missing data between PDUs" },
    { CountType::SUM, "exceeded_max_segs",
        "number of times the maximum queued segment limit was reached" },
    { CountType::SUM, "exceeded_max_bytes",
        "number of times the maximum queued byte limit was reached" },
    { CountType::SUM, "internal_events", "135:X events generated" },
    { CountType::SUM, "client_cleanups",
        "number of times data from server was flushed when session released" },
    { CountType::SUM, "server_cleanups",
        "number of times data from client was flushed when session released" },
    { CountType::NOW, "memory", "current memory in use" },
    { CountType::NOW, "initializing", "number of sessions currently initializing" },
    { CountType::NOW, "established", "number of sessions currently established" },
    { CountType::NOW, "closing", "number of sessions currently closing" },
    { CountType::SUM, "syns", "number of syn packets" },
    { CountType::SUM, "syn_acks", "number of syn-ack packets" },
    { CountType::SUM, "resets", "number of reset packets" },
    { CountType::SUM, "fins", "number of fin packets"},
    { CountType::END, nullptr, nullptr }
};

THREAD_LOCAL TcpStats tcpStats;

#define STREAM_TCP_SYN_ON_EST_STR \
    "SYN on established session"
#define STREAM_TCP_DATA_ON_SYN_STR \
    "data on SYN packet"
#define STREAM_TCP_DATA_ON_CLOSED_STR \
    "data sent on stream not accepting data"
#define STREAM_TCP_BAD_TIMESTAMP_STR \
    "TCP timestamp is outside of PAWS window"
#define STREAM_TCP_BAD_SEGMENT_STR \
    "bad segment, adjusted size <= 0 (deprecated)"
#define STREAM_TCP_WINDOW_TOO_LARGE_STR \
    "window size (after scaling) larger than policy allows"
#define STREAM_TCP_EXCESSIVE_TCP_OVERLAPS_STR \
    "limit on number of overlapping TCP packets reached"
#define STREAM_TCP_DATA_AFTER_RESET_STR \
    "data sent on stream after TCP reset sent"
#define STREAM_TCP_SESSION_HIJACKED_CLIENT_STR \
    "TCP client possibly hijacked, different ethernet address"
#define STREAM_TCP_SESSION_HIJACKED_SERVER_STR \
    "TCP server possibly hijacked, different ethernet address"
#define STREAM_TCP_DATA_WITHOUT_FLAGS_STR \
    "TCP data with no TCP flags set"
#define STREAM_TCP_SMALL_SEGMENT_STR \
    "consecutive TCP small segments exceeding threshold"
#define STREAM_TCP_4WAY_HANDSHAKE_STR \
    "4-way handshake detected"
#define STREAM_TCP_NO_TIMESTAMP_STR \
    "TCP timestamp is missing"
#define STREAM_TCP_BAD_RST_STR \
    "reset outside window"
#define STREAM_TCP_BAD_FIN_STR \
    "FIN number is greater than prior FIN"
#define STREAM_TCP_BAD_ACK_STR \
    "ACK number is greater than prior FIN"
#define STREAM_TCP_DATA_AFTER_RST_RCVD_STR \
    "data sent on stream after TCP reset received"
#define STREAM_TCP_WINDOW_SLAM_STR \
    "TCP window closed before receiving data"
#define STREAM_TCP_NO_3WHS_STR \
    "TCP session without 3-way handshake"

static const Parameter stream_tcp_small_params[] =
{
    { "count", Parameter::PT_INT, "0:2048", "0",
      "limit number of small segments queued" },

    { "maximum_size", Parameter::PT_INT, "0:2048", "0",
      "limit number of small segments queued" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter stream_queue_limit_params[] =
{
    { "max_bytes", Parameter::PT_INT, "0:", "1048576",
      "don't queue more than given bytes per session and direction" },

    { "max_segments", Parameter::PT_INT, "0:", "2621",
      "don't queue more than given segments per session and direction" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "flush_factor", Parameter::PT_INT, "0:", "0",
      "flush upon seeing a drop in segment size after given number of non-decreasing segments" },

    { "max_window", Parameter::PT_INT, "0:1073725440", "0",
      "maximum allowed TCP window" },

    { "overlap_limit", Parameter::PT_INT, "0:255", "0",
      "maximum number of allowed overlapping segments per session" },

    { "max_pdu", Parameter::PT_INT, "1460:32768", "16384",
      "maximum reassembled PDU size" },

    { "policy", Parameter::PT_ENUM, TCP_POLICIES, "bsd",
      "determines operating system characteristics like reassembly" },

    { "reassemble_async", Parameter::PT_BOOL, nullptr, "true",
      "queue data for reassembly before traffic is seen in both directions" },

    { "require_3whs", Parameter::PT_INT, "-1:86400", "-1",
      "don't track midstream sessions after given seconds from start up; -1 tracks all" },

    { "show_rebuilt_packets", Parameter::PT_BOOL, nullptr, "false",
      "enable cmg like output of reassembled packets" },

    { "queue_limit", Parameter::PT_TABLE, stream_queue_limit_params, nullptr,
      "limit amount of segment data queued" },

    { "small_segments", Parameter::PT_TABLE, stream_tcp_small_params, nullptr,
      "limit number of small segments queued" },

    { "session_timeout", Parameter::PT_INT, "1:86400", "30",
      "session tracking timeout" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap stream_tcp_rules[] =
{
    { STREAM_TCP_SYN_ON_EST, STREAM_TCP_SYN_ON_EST_STR },
    { STREAM_TCP_DATA_ON_SYN, STREAM_TCP_DATA_ON_SYN_STR },
    { STREAM_TCP_DATA_ON_CLOSED, STREAM_TCP_DATA_ON_CLOSED_STR },
    { STREAM_TCP_BAD_TIMESTAMP, STREAM_TCP_BAD_TIMESTAMP_STR },
    { STREAM_TCP_BAD_SEGMENT, STREAM_TCP_BAD_SEGMENT_STR },
    { STREAM_TCP_WINDOW_TOO_LARGE, STREAM_TCP_WINDOW_TOO_LARGE_STR },
    { STREAM_TCP_EXCESSIVE_TCP_OVERLAPS, STREAM_TCP_EXCESSIVE_TCP_OVERLAPS_STR },
    { STREAM_TCP_DATA_AFTER_RESET, STREAM_TCP_DATA_AFTER_RESET_STR },
    { STREAM_TCP_SESSION_HIJACKED_CLIENT, STREAM_TCP_SESSION_HIJACKED_CLIENT_STR },
    { STREAM_TCP_SESSION_HIJACKED_SERVER, STREAM_TCP_SESSION_HIJACKED_SERVER_STR },
    { STREAM_TCP_DATA_WITHOUT_FLAGS, STREAM_TCP_DATA_WITHOUT_FLAGS_STR },
    { STREAM_TCP_SMALL_SEGMENT, STREAM_TCP_SMALL_SEGMENT_STR },
    { STREAM_TCP_4WAY_HANDSHAKE, STREAM_TCP_4WAY_HANDSHAKE_STR },
    { STREAM_TCP_NO_TIMESTAMP, STREAM_TCP_NO_TIMESTAMP_STR },
    { STREAM_TCP_BAD_RST, STREAM_TCP_BAD_RST_STR },
    { STREAM_TCP_BAD_FIN, STREAM_TCP_BAD_FIN_STR },
    { STREAM_TCP_BAD_ACK, STREAM_TCP_BAD_ACK_STR },
    { STREAM_TCP_DATA_AFTER_RST_RCVD, STREAM_TCP_DATA_AFTER_RST_RCVD_STR },
    { STREAM_TCP_WINDOW_SLAM, STREAM_TCP_WINDOW_SLAM_STR },
    { STREAM_TCP_NO_3WHS, STREAM_TCP_NO_3WHS_STR },

    { 0, nullptr }
};

StreamTcpModule::StreamTcpModule() :
    Module(MOD_NAME, MOD_HELP, s_params)
{
    config = nullptr;
}


const RuleMap* StreamTcpModule::get_rules() const
{ return stream_tcp_rules; }

ProfileStats* StreamTcpModule::get_profile(
    unsigned index, const char*& name, const char*& parent) const
{
    switch ( index )
    {
    case 0:
        name = MOD_NAME;
        parent = nullptr;
        return &s5TcpPerfStats;

    case 1:
        name = "tcpNewSess";
        parent = "stream_tcp";
        return &s5TcpNewSessPerfStats;

    case 2:
        name = "tcpState";
        parent = "stream_tcp";
        return &s5TcpStatePerfStats;

    case 3:
        name = "tcpData";
        parent = "tcpState";
        return &s5TcpDataPerfStats;

    case 4:
        name = "tcpPktInsert";
        parent = "tcpData";
        return &s5TcpInsertPerfStats;

    case 5:
        name = "tcpPAF";
        parent = "tcpState";
        return &s5TcpPAFPerfStats;

    case 6:
        name = "tcpFlush";
        parent = "tcpState";
        return &s5TcpFlushPerfStats;

    case 7:
        name = "tcpBuildPacket";
        parent = "tcpFlush";
        return &s5TcpBuildPacketPerfStats;
    }
    return nullptr;
}

TcpStreamConfig* StreamTcpModule::get_data()
{
    TcpStreamConfig* temp = config;
    config = nullptr;
    return temp;
}

bool StreamTcpModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("count") )
        config->max_consec_small_segs = v.get_long();

    else if ( v.is("maximum_size") )
        config->max_consec_small_seg_size = v.get_long();

    else if ( v.is("flush_factor") )
        config->flush_factor = v.get_long();

    else if ( v.is("max_bytes") )
        config->max_queued_bytes = v.get_long();

    else if ( v.is("max_segments") )
        config->max_queued_segs = v.get_long();

    else if ( v.is("max_window") )
        config->max_window = v.get_long();

    else if ( v.is("max_pdu") )
        config->paf_max = v.get_long();

    else if ( v.is("policy") )
        config->policy = static_cast< StreamPolicy >( v.get_long() + 1 );

    else if ( v.is("overlap_limit") )
        config->overlap_limit = v.get_long();

    else if ( v.is("session_timeout") )
        config->session_timeout = v.get_long();

    else if ( v.is("reassemble_async") )
    {
        if ( v.get_bool() )
            config->flags &= ~STREAM_CONFIG_NO_ASYNC_REASSEMBLY;
        else
            config->flags |= STREAM_CONFIG_NO_ASYNC_REASSEMBLY;
    }
    else if ( v.is("require_3whs") )
    {
        config->hs_timeout = v.get_long();
    }
    else if ( v.is("show_rebuilt_packets") )
    {
        if ( v.get_bool() )
            config->flags |= STREAM_CONFIG_SHOW_PACKETS;
        else
            config->flags &= ~STREAM_CONFIG_SHOW_PACKETS;
    }
    else
        return false;

    return true;
}

bool StreamTcpModule::begin(const char* fqn, int, SnortConfig*)
{
    if ( !strcmp(fqn, "stream_tcp.small_segments") ||
        !strcmp(fqn, "stream_tcp.queue_limit"))
    {
        return true;
    }

    if ( config )
        return false;

    config = new TcpStreamConfig;
    return true;
}

bool StreamTcpModule::end(const char*, int, SnortConfig* sc)
{
    if ( config->hs_timeout >= 0 )
        sc->run_flags |= RUN_FLAG__TRACK_ON_SYN;
    return true;
}

const PegInfo* StreamTcpModule::get_pegs() const
{ return tcp_pegs; }

PegCount* StreamTcpModule::get_counts() const
{ return (PegCount*)&tcpStats; }

