//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

// log_text.h author Russ Combs <rcombs@sourcefire.com>

#ifndef LOG_TEXT_H
#define LOG_TEXT_H

// Use these methods to write to a TextLog

#include "log/text_log.h"

struct Event;

namespace snort
{
struct Packet;
namespace ip { struct IP4Hdr; }
namespace tcp { struct TCPHdr; }

SO_PUBLIC void LogTimeStamp(TextLog*, Packet*);
SO_PUBLIC void LogPriorityData(TextLog*, const Event&);
SO_PUBLIC void LogXrefs(TextLog*, const Event&);

SO_PUBLIC void LogIPPkt(TextLog*, Packet*);
SO_PUBLIC void LogPayload(TextLog*, Packet*);
SO_PUBLIC bool LogAppID(TextLog*, Packet*);

SO_PUBLIC void LogNetData(
    TextLog*, const uint8_t* data, const int len, Packet*, const char* buf_name = nullptr);

SO_PUBLIC void Log2ndHeader(TextLog*, Packet*);
SO_PUBLIC void LogTCPHeader(TextLog*, Packet*);
SO_PUBLIC void LogUDPHeader(TextLog*, Packet*);
SO_PUBLIC void LogICMPHeader(TextLog*, Packet*);

SO_PUBLIC void LogIpAddrs(TextLog*, Packet*);
SO_PUBLIC void LogIPHeader(TextLog*, Packet*);

SO_PUBLIC void LogIpOptions(TextLog*, const ip::IP4Hdr*, uint16_t valid_ip4_len);
SO_PUBLIC void LogTcpOptions(TextLog*, const tcp::TCPHdr*, uint16_t valid_tcp_len);
}

#endif

