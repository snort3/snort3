//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

// tcp_event_logger.cc author davis mcpherson <davmcphe@cisco.com>
// Created on: Jul 30, 2015

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_event_logger.h"

#include "detection/detection_engine.h"
#include "detection/rules.h"
#include "filters/sfrf.h"
#include "main/snort_config.h"
#include "packet_io/packet_tracer.h"

#include "tcp_module.h"

using namespace snort;

struct tcp_event_sid
{
    uint32_t event_id;
    uint32_t sid;
    const char* event_description;
};

// ffs returns 1 as bit position of lsb so event id array
// has dummy entry for index 0
struct tcp_event_sid tcp_event_sids[] =
{
    { 0, 0, nullptr },
    { EVENT_SYN_ON_EST, STREAM_TCP_SYN_ON_EST, "SYN_ON_EST" },
    { EVENT_DATA_ON_SYN, STREAM_TCP_DATA_ON_SYN, "DATA_ON_SYN" },
    { EVENT_DATA_ON_CLOSED, STREAM_TCP_DATA_ON_CLOSED, "DATA_ON_CLOSED" },
    { EVENT_BAD_TIMESTAMP, STREAM_TCP_BAD_TIMESTAMP, "BAD_TIMESTAMP" },
    { EVENT_WINDOW_TOO_LARGE, STREAM_TCP_WINDOW_TOO_LARGE, "WINDOW_TOO_LARGE" },
    { EVENT_DATA_AFTER_RESET, STREAM_TCP_DATA_AFTER_RESET, "DATA_AFTER_RESET" },
    { EVENT_SESSION_HIJACK_CLIENT, STREAM_TCP_SESSION_HIJACKED_CLIENT, "SESSION_HIJACK_CLIENT" },
    { EVENT_SESSION_HIJACK_SERVER, STREAM_TCP_SESSION_HIJACKED_SERVER, "SESSION_HIJACK_SERVER" },
    { EVENT_DATA_WITHOUT_FLAGS, STREAM_TCP_DATA_WITHOUT_FLAGS, "DATA_WITHOUT_FLAGS" },
    { EVENT_4WHS, STREAM_TCP_4WAY_HANDSHAKE, "4WHS" },
    { EVENT_NO_TIMESTAMP, STREAM_TCP_NO_TIMESTAMP, "NO_TIMESTAMP" },
    { EVENT_BAD_RST, STREAM_TCP_BAD_RST, "BAD_RST" },
    { EVENT_BAD_FIN, STREAM_TCP_BAD_FIN, "BAD_FIN" },
    { EVENT_BAD_ACK, STREAM_TCP_BAD_ACK, "BAD_ACK" },
    { EVENT_DATA_AFTER_RST_RCVD, STREAM_TCP_DATA_AFTER_RST_RCVD, "DATA_AFTER_RST_RCVD" },
    { EVENT_WINDOW_SLAM, STREAM_TCP_WINDOW_SLAM, "WINDOW_SLAM" },
    { EVENT_NO_3WHS, STREAM_TCP_NO_3WHS, "NO_3WHS" },
    { EVENT_EXCESSIVE_OVERLAP, STREAM_TCP_EXCESSIVE_TCP_OVERLAPS, "EXCESSIVE_OVERLAP" },
    { EVENT_MAX_SMALL_SEGS_EXCEEDED, STREAM_TCP_SMALL_SEGMENT, "MAX_SMALL_SEGS_EXCEEDED" },
    { EVENT_MAX_QUEUED_BYTES_EXCEEDED, STREAM_TCP_MAX_QUEUED_BYTES_EXCEEDED, "MAX_QUEUED_BYTES_EXCEEDED" },
    { EVENT_MAX_QUEUED_SEGS_EXCEEDED, STREAM_TCP_MAX_QUEUED_SEGS_EXCEEDED, "MAX_QUEUED_SEGS_EXCEEDED" },
    { 0, 0, nullptr }, { 0, 0, nullptr }, { 0, 0, nullptr }, { 0, 0, nullptr }
};

void TcpEventLogger::log_internal_event(uint32_t eventSid)
{
    if (is_internal_event_enabled(SnortConfig::get_conf()->rate_filter_config, eventSid))
    {
        tcpStats.internalEvents++;
        DetectionEngine::queue_event(GID_SESSION, eventSid);
    }
}

void TcpEventLogger::log_tcp_events()
{
    while ( tcp_events )
    {
        uint32_t idx = ffs(tcp_events);
        if ( idx )
        {
            DetectionEngine::queue_event(GID_STREAM_TCP, tcp_event_sids[idx].sid);
            if ( PacketTracer::is_active() )
                PacketTracer::log("stream_tcp: TCP raised %u:%u %s\n",
                    GID_STREAM_TCP, tcp_event_sids[idx].sid,
                    tcp_event_sids[idx].event_description);
            tcp_events ^= tcp_event_sids[idx].event_id;
            tcpStats.events++;
        }
    }
}

