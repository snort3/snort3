//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// tcp_events.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 30, 2015

#ifndef TCP_EVENTS_H
#define TCP_EVENTS_H

#include "main/snort_config.h"
#include "events/event_queue.h"
#include "filters/sfrf.h"
#include "detection/rules.h"
#include "tcp_defs.h"
#include "tcp_module.h"

/* events */
#define EVENT_SYN_ON_EST                0x00000001
#define EVENT_DATA_ON_SYN               0x00000002
#define EVENT_DATA_ON_CLOSED            0x00000004
#define EVENT_BAD_TIMESTAMP             0x00000008
#define EVENT_WINDOW_TOO_LARGE          0x00000010
#define EVENT_DATA_AFTER_RESET          0x00000020
#define EVENT_SESSION_HIJACK_CLIENT     0x00000040
#define EVENT_SESSION_HIJACK_SERVER     0x00000080
#define EVENT_DATA_WITHOUT_FLAGS        0x00000100
#define EVENT_4WHS                      0x00000200
#define EVENT_NO_TIMESTAMP              0x00000400
#define EVENT_BAD_RST                   0x00000800
#define EVENT_BAD_FIN                   0x00001000
#define EVENT_BAD_ACK                   0x00002000
#define EVENT_DATA_AFTER_RST_RCVD       0x00004000
#define EVENT_WINDOW_SLAM               0x00008000
#define EVENT_NO_3WHS                   0x00010000

static inline void EventSynOnEst()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SYN_ON_EST);
    tcpStats.events++;
}

static inline void EventExcessiveOverlap()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_EXCESSIVE_TCP_OVERLAPS);
    tcpStats.events++;
}

static inline void EventBadTimestamp()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_TIMESTAMP);
    tcpStats.events++;
}

static inline void EventWindowTooLarge()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_WINDOW_TOO_LARGE);
    tcpStats.events++;
}

static inline void EventDataOnSyn()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_ON_SYN);
    tcpStats.events++;
}

static inline void EventDataOnClosed()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_ON_CLOSED);
    tcpStats.events++;
}

static inline void EventDataAfterReset()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_AFTER_RESET);
    tcpStats.events++;
}

static inline void EventBadSegment()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_SEGMENT);
    tcpStats.events++;
}

static inline void EventSessionHijackedClient()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SESSION_HIJACKED_CLIENT);
    tcpStats.events++;
}

static inline void EventSessionHijackedServer()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SESSION_HIJACKED_SERVER);
    tcpStats.events++;
}

static inline void EventDataWithoutFlags()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_WITHOUT_FLAGS);
    tcpStats.events++;
}

static inline void EventMaxSmallSegsExceeded()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SMALL_SEGMENT);
    tcpStats.events++;
}

static inline void Event4whs()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_4WAY_HANDSHAKE);
    tcpStats.events++;
}

static inline void EventNoTimestamp()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_NO_TIMESTAMP);
    tcpStats.events++;
}

static inline void EventBadReset()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_RST);
    tcpStats.events++;
}

static inline void EventBadFin()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_FIN);
    tcpStats.events++;
}

static inline void EventBadAck()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_ACK);
    tcpStats.events++;
}

static inline void EventDataAfterRstRcvd()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_AFTER_RST_RCVD);
    tcpStats.events++;
}

static inline void EventInternal(uint32_t eventSid)
{
    if (!InternalEventIsEnabled(snort_conf->rate_filter_config, eventSid))
        return;

    tcpStats.internalEvents++;

    STREAM_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE, "Stream raised internal event %d\n", eventSid); );

    SnortEventqAdd(GENERATOR_INTERNAL, eventSid);
}

static inline void EventWindowSlam()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_WINDOW_SLAM);
    tcpStats.events++;
}

static inline void EventNo3whs()
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_NO_3WHS);
    tcpStats.events++;
}

static inline void LogTcpEvents(int eventcode)
{
    if (!eventcode)
        return;

    if (eventcode & EVENT_SYN_ON_EST)
        EventSynOnEst();

    if (eventcode & EVENT_DATA_ON_SYN)
        EventDataOnSyn();

    if (eventcode & EVENT_DATA_ON_CLOSED)
        EventDataOnClosed();

    if (eventcode & EVENT_BAD_TIMESTAMP)
        EventBadTimestamp();

    if (eventcode & EVENT_WINDOW_TOO_LARGE)
        EventWindowTooLarge();

    if (eventcode & EVENT_DATA_AFTER_RESET)
        EventDataAfterReset();

    if (eventcode & EVENT_SESSION_HIJACK_CLIENT)
        EventSessionHijackedClient();

    if (eventcode & EVENT_SESSION_HIJACK_SERVER)
        EventSessionHijackedServer();

    if (eventcode & EVENT_DATA_WITHOUT_FLAGS)
        EventDataWithoutFlags();

    if (eventcode & EVENT_4WHS)
        Event4whs();

    if (eventcode & EVENT_NO_TIMESTAMP)
        EventNoTimestamp();

    if (eventcode & EVENT_BAD_RST)
        EventBadReset();

    if (eventcode & EVENT_BAD_FIN)
        EventBadFin();

    if (eventcode & EVENT_BAD_ACK)
        EventBadAck();

    if (eventcode & EVENT_DATA_AFTER_RST_RCVD)
        EventDataAfterRstRcvd();

    if (eventcode & EVENT_WINDOW_SLAM)
        EventWindowSlam();
}

#endif
