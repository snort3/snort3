//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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
#include "tcp_normalizer.h"

#include "main/snort_config.h"
#include "profiler/profiler_defs.h"
#include "stream/paf.h"
#include "stream/paf_stats.h"
#include "trace/trace.h"

#include "tcp_trace.h"

using namespace snort;

//-------------------------------------------------------------------------
// stream_tcp module
//-------------------------------------------------------------------------

THREAD_LOCAL ProfileStats s5TcpPerfStats;

THREAD_LOCAL const Trace* stream_tcp_trace = nullptr;

#ifdef DEBUG_MSGS
static const TraceOption stream_tcp_trace_options[] =
{
    { "segments", TRACE_SEGMENTS, "enable stream TCP segments trace logging" },
    { "state",    TRACE_STATE,    "enable stream TCP state trace logging" },

    { nullptr, 0, nullptr }
};
#endif

const PegInfo tcp_pegs[] =
{
    SESSION_PEGS("tcp"),
    { CountType::SUM, "instantiated", "new sessions instantiated" },
    { CountType::SUM, "setups", "session initializations" },
    { CountType::SUM, "restarts", "sessions restarted" },
    { CountType::SUM, "resyns", "SYN received on established session" },
    { CountType::SUM, "discards", "tcp packets discarded" },
    { CountType::SUM, "discards_skipped", "tcp packet discards skipped due to normalization disabled" },
    { CountType::SUM, "invalid_seq_num", "tcp packets received with an invalid sequence number" },
    { CountType::SUM, "invalid_ack", "tcp packets received with an invalid ack number" },
    { CountType::SUM, "no_flags_set", "tcp packets received with no TCP flags set" },
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
    { CountType::SUM, "payload_fully_trimmed", "segments with no data after trimming" },
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
    { CountType::SUM, "fins", "number of fin packets" },
    { CountType::SUM, "meta_acks", "number of meta acks processed" },
    { CountType::SUM, "packets_held", "number of packets held" },
    { CountType::SUM, "held_packet_rexmits", "number of retransmits of held packets" },
    { CountType::SUM, "held_packets_dropped", "number of held packets dropped" },
    { CountType::SUM, "held_packets_passed", "number of held packets passed" },
    { CountType::SUM, "held_packet_timeouts", "number of held packets that timed out" },
    { CountType::SUM, "held_packet_purges", "number of held packets that were purged without flushing" },
    { CountType::SUM, "held_packet_retries", "number of held packets that were added to the retry queue" },
    { CountType::NOW, "cur_packets_held", "number of packets currently held" },
    { CountType::MAX, "max_packets_held", "maximum number of packets held simultaneously" },
    { CountType::SUM, "partial_flushes", "number of partial flushes initiated" },
    { CountType::SUM, "partial_flush_bytes", "partial flush total bytes" },
    { CountType::SUM, "inspector_fallbacks", "count of fallbacks from assigned service inspector" },
    { CountType::SUM, "partial_fallbacks", "count of fallbacks from assigned service stream splitter" },
    { CountType::MAX, "max_segs", "maximum number of segments queued in any flow" },
    { CountType::MAX, "max_bytes", "maximum number of bytes queued in any flow" },
    { CountType::SUM, "zero_len_tcp_opt", "number of zero length tcp options" },
    { CountType::SUM, "zero_win_probes", "number of tcp zero window probes" },
    { CountType::SUM, "keep_alive_probes", "number of tcp keep-alive probes" },
    { CountType::SUM, "proxy_mode_flows", "number of flows set to proxy normalization policy" },
    { CountType::SUM, "full_retransmits", "number of fully retransmitted segments" },
    { CountType::SUM, "flush_on_asymmetric_flow", "number of flushes on asymmetric flows" },
    { CountType::SUM, "asymmetric_flows", "number of completed flows having one-way traffic only" },
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
#define STREAM_TCP_MAX_QUEUED_BYTES_STR \
    "TCP max queued reassembly bytes exceeded threshold"
#define STREAM_TCP_MAX_QUEUED_SEGS_STR \
    "TCP max queued reassembly segments exceeded threshold"

static const Parameter stream_tcp_small_params[] =
{
    { "count", Parameter::PT_INT, "0:2048", "0",
      "number of consecutive (in the received order) TCP small segments considered to be excessive (129:12)" },

    { "maximum_size", Parameter::PT_INT, "0:2048", "0",
      "minimum bytes for a TCP segment not to be considered small (129:12)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter stream_queue_limit_params[] =
{
    { "max_bytes", Parameter::PT_INT, "0:max32", "4194304",
      "don't queue more than given bytes per session and direction, 0 = unlimited" },

    { "max_segments", Parameter::PT_INT, "0:max32", "3072",
      "don't queue more than given segments per session and direction, 0 = unlimited" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "flush_factor", Parameter::PT_INT, "0:65535", "0",
      "flush upon seeing a drop in segment size after given number of non-decreasing segments" },

    { "max_window", Parameter::PT_INT, "0:1073725440", "0",
      "maximum allowed TCP window" },

    { "overlap_limit", Parameter::PT_INT, "0:max32", "0",
      "maximum number of allowed overlapping segments per session" },

    { "max_pdu", Parameter::PT_INT, "1460:32768", "16384",
      "maximum reassembled PDU size" },

    { "no_ack", Parameter::PT_BOOL, nullptr, "false",
      "received data is implicitly acked immediately" },

    { "policy", Parameter::PT_ENUM, TCP_POLICIES, "bsd",
      "determines operating system characteristics like reassembly" },

    { "reassemble_async", Parameter::PT_BOOL, nullptr, "true",
      "queue data for reassembly before traffic is seen in both directions" },

    { "require_3whs", Parameter::PT_INT, "-1:max31", "-1",
      "don't track midstream sessions after given seconds from start up; -1 tracks all" },

    { "show_rebuilt_packets", Parameter::PT_BOOL, nullptr, "false",
      "enable cmg like output of reassembled packets" },

    { "queue_limit", Parameter::PT_TABLE, stream_queue_limit_params, nullptr,
      "limit amount of segment data queued" },

    { "small_segments", Parameter::PT_TABLE, stream_tcp_small_params, nullptr,
      "limit number of small segments queued" },

    { "session_timeout", Parameter::PT_INT, "1:max31", "180",
      "session tracking timeout" },

    { "track_only", Parameter::PT_BOOL, nullptr, "false",
      "disable reassembly if true" },

    { "embryonic_timeout", Parameter::PT_INT, "1:max31", "30",
      "Non-established connection timeout" },

    { "idle_timeout", Parameter::PT_INT, "1:max31", "3600",
      "session deletion on idle " },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap stream_tcp_rules[] =
{
    { STREAM_TCP_SYN_ON_EST, STREAM_TCP_SYN_ON_EST_STR },
    { STREAM_TCP_DATA_ON_SYN, STREAM_TCP_DATA_ON_SYN_STR },
    { STREAM_TCP_DATA_ON_CLOSED, STREAM_TCP_DATA_ON_CLOSED_STR },
    { STREAM_TCP_BAD_TIMESTAMP, STREAM_TCP_BAD_TIMESTAMP_STR },
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
    { STREAM_TCP_MAX_QUEUED_BYTES_EXCEEDED, STREAM_TCP_MAX_QUEUED_BYTES_STR },
    { STREAM_TCP_MAX_QUEUED_SEGS_EXCEEDED, STREAM_TCP_MAX_QUEUED_SEGS_STR },

    { 0, nullptr }
};

StreamTcpModule::StreamTcpModule() :
    Module(STREAM_TCP_MOD_NAME, STREAM_TCP_MOD_HELP, s_params)
{
    config = nullptr;
}

void StreamTcpModule::set_trace(const Trace* trace) const
{ stream_tcp_trace = trace; }

const TraceOption* StreamTcpModule::get_trace_options() const
{
#ifndef DEBUG_MSGS
    return nullptr;
#else
    return stream_tcp_trace_options;
#endif
}

const RuleMap* StreamTcpModule::get_rules() const
{ return stream_tcp_rules; }

ProfileStats* StreamTcpModule::get_profile(
    unsigned index, const char*& name, const char*& parent) const
{
    switch ( index )
    {
    case 0:
        name = STREAM_TCP_MOD_NAME;
        parent = nullptr;
        return &s5TcpPerfStats;

    case 1:
        name = "paf";
        parent = nullptr;
        return &pafPerfStats;
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
        config->max_consec_small_segs = v.get_uint16();

    else if ( v.is("maximum_size") )
        config->max_consec_small_seg_size = v.get_uint16();

    else if ( v.is("flush_factor") )
        config->flush_factor = v.get_uint16();

    else if ( v.is("max_bytes") )
        config->max_queued_bytes = v.get_uint32();

    else if ( v.is("max_segments") )
        config->max_queued_segs = v.get_uint32();

    else if ( v.is("max_window") )
        config->max_window = v.get_uint32();

    else if ( v.is("max_pdu") )
        config->paf_max = v.get_uint16();

    else if ( v.is("no_ack") )
        config->no_ack = v.get_bool();

    else if ( v.is("policy") )
        config->policy = static_cast< StreamPolicy >( v.get_uint8() );

    else if ( v.is("overlap_limit") )
        config->overlap_limit = v.get_uint32();

    else if ( v.is("session_timeout") )
        config->session_timeout = v.get_uint32();

    else if ( v.is("embryonic_timeout") )
        config->embryonic_timeout = v.get_uint32();

    else if ( v.is("idle_timeout") )
        config->idle_timeout = v.get_uint32();

    else if ( v.is("reassemble_async") )
    {
        if ( v.get_bool() )
            config->flags &= ~STREAM_CONFIG_NO_ASYNC_REASSEMBLY;
        else
            config->flags |= STREAM_CONFIG_NO_ASYNC_REASSEMBLY;
    }

    else if ( v.is("require_3whs") )
    {
        config->hs_timeout = v.get_int32();
    }

    else if ( v.is("show_rebuilt_packets") )
    {
        if ( v.get_bool() )
            config->flags |= STREAM_CONFIG_SHOW_PACKETS;
        else
            config->flags &= ~STREAM_CONFIG_SHOW_PACKETS;
    }

    else if ( v.is("track_only") )
    {
        if ( v.get_bool() )
            config->flags |= STREAM_CONFIG_NO_REASSEMBLY;
        else
            config->flags &= ~STREAM_CONFIG_NO_REASSEMBLY;
    }

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
        sc->set_run_flags(RUN_FLAG__TRACK_ON_SYN);
    return true;
}

const PegInfo* StreamTcpModule::get_pegs() const
{ return tcp_pegs; }

PegCount* StreamTcpModule::get_counts() const
{ return (PegCount*)&tcpStats; }

void StreamTcpModule::reset_stats()
{
    TcpNormalizer::reset_stats();
    Module::reset_stats();
}
