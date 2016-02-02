//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

// tcp_events.cc author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 30, 2015

#include "main/snort_config.h"
#include "events/event_queue.h"
#include "filters/sfrf.h"
#include "detection/rules.h"

#include "tcp_defs.h"
#include "tcp_module.h"
#include "tcp_event_logger.h"

void TcpEventLogger::set_tcp_internal_syn_event(void)
{
    tcp_events |= INTERNAL_EVENT_SYN_RECEIVED;
}

void TcpEventLogger::EventSynOnEst(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SYN_ON_EST);
    tcpStats.events++;
}

void TcpEventLogger::EventExcessiveOverlap(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_EXCESSIVE_TCP_OVERLAPS);
    tcpStats.events++;
}

void TcpEventLogger::EventBadTimestamp(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_TIMESTAMP);
    tcpStats.events++;
}

void TcpEventLogger::EventWindowTooLarge(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_WINDOW_TOO_LARGE);
    tcpStats.events++;
}

void TcpEventLogger::EventDataOnSyn(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_ON_SYN);
    tcpStats.events++;
}

void TcpEventLogger::EventDataOnClosed(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_ON_CLOSED);
    tcpStats.events++;
}

void TcpEventLogger::EventDataAfterReset(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_AFTER_RESET);
    tcpStats.events++;
}

void TcpEventLogger::EventBadSegment(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_SEGMENT);
    tcpStats.events++;
}

void TcpEventLogger::EventSessionHijackedClient(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SESSION_HIJACKED_CLIENT);
    tcpStats.events++;
}

void TcpEventLogger::EventSessionHijackedServer(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SESSION_HIJACKED_SERVER);
    tcpStats.events++;
}

void TcpEventLogger::EventDataWithoutFlags(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_WITHOUT_FLAGS);
    tcpStats.events++;
}

void TcpEventLogger::EventMaxSmallSegsExceeded(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_SMALL_SEGMENT);
    tcpStats.events++;
}

void TcpEventLogger::Event4whs(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_4WAY_HANDSHAKE);
    tcpStats.events++;
}

void TcpEventLogger::EventNoTimestamp(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_NO_TIMESTAMP);
    tcpStats.events++;
}

void TcpEventLogger::EventBadReset(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_RST);
    tcpStats.events++;
}

void TcpEventLogger::EventBadFin(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_FIN);
    tcpStats.events++;
}

void TcpEventLogger::EventBadAck(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_BAD_ACK);
    tcpStats.events++;
}

void TcpEventLogger::EventDataAfterRstRcvd(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_DATA_AFTER_RST_RCVD);
    tcpStats.events++;
}

void TcpEventLogger::EventInternal(uint32_t eventSid)
{
    if (!InternalEventIsEnabled(snort_conf->rate_filter_config, eventSid))
        return;

    tcpStats.internalEvents++;

    STREAM_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, "Stream raised internal event %d\n",
        eventSid); );

    SnortEventqAdd(GENERATOR_INTERNAL, eventSid);
}

void TcpEventLogger::EventWindowSlam(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_WINDOW_SLAM);
    tcpStats.events++;
}

void TcpEventLogger::EventNo3whs(void)
{
    SnortEventqAdd(GID_STREAM_TCP, STREAM_TCP_NO_3WHS);
    tcpStats.events++;
}

void TcpEventLogger::log_tcp_events(void)
{
    if ( !tcp_events )
        return;

    if (tcp_events & EVENT_SYN_ON_EST)
        EventSynOnEst();

    if (tcp_events & EVENT_DATA_ON_SYN)
        EventDataOnSyn();

    if (tcp_events & EVENT_DATA_ON_CLOSED)
        EventDataOnClosed();

    if (tcp_events & EVENT_BAD_TIMESTAMP)
        EventBadTimestamp();

    if (tcp_events & EVENT_WINDOW_TOO_LARGE)
        EventWindowTooLarge();

    if (tcp_events & EVENT_DATA_AFTER_RESET)
        EventDataAfterReset();

    if (tcp_events & EVENT_SESSION_HIJACK_CLIENT)
        EventSessionHijackedClient();

    if (tcp_events & EVENT_SESSION_HIJACK_SERVER)
        EventSessionHijackedServer();

    if (tcp_events & EVENT_DATA_WITHOUT_FLAGS)
        EventDataWithoutFlags();

    if (tcp_events & EVENT_4WHS)
        Event4whs();

    if (tcp_events & EVENT_NO_TIMESTAMP)
        EventNoTimestamp();

    if (tcp_events & EVENT_BAD_RST)
        EventBadReset();

    if (tcp_events & EVENT_BAD_FIN)
        EventBadFin();

    if (tcp_events & EVENT_BAD_ACK)
        EventBadAck();

    if (tcp_events & EVENT_DATA_AFTER_RST_RCVD)
        EventDataAfterRstRcvd();

    if (tcp_events & EVENT_WINDOW_SLAM)
        EventWindowSlam();

    tcp_events = 0;
}

