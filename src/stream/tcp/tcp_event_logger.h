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

// tcp_event_logger.h author davis mcpherson <davmcphe@@cisco.com>
// Created on: Jul 30, 2015

#ifndef TCP_EVENT_LOGGER_H
#define TCP_EVENT_LOGGER_H

#include <cstdint>

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
#define EVENT_BAD_SEGMENT               0x00020000
#define EVENT_EXCESSIVE_OVERLAP         0x00040000
#define EVENT_MAX_SMALL_SEGS_EXCEEDED   0x00080000

class TcpEventLogger
{
public:
    TcpEventLogger() = default;


    void clear_tcp_events()
    {
        tcp_events = 0;
    }

    void set_tcp_event(int eventcode)
    {
        tcp_events |= eventcode;
    }

    void set_tcp_internal_syn_event();
    void log_tcp_events();
    void log_internal_event(uint32_t eventSid);

private:
    uint32_t tcp_events = 0;
};
#endif

