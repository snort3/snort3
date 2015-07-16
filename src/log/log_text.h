//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#include <stdint.h>
#include "log/text_log.h"
#include "main/snort_types.h"

struct Packet;
struct Event;

namespace ip { struct IP4Hdr; }
namespace tcp { struct TCPHdr; }

typedef ip::IP4Hdr IP4Hdr;

void LogPriorityData(TextLog*, const Event*, bool doNewLine);
void LogXrefs(TextLog*, const Event*, bool doNewLine);

void LogIPPkt(TextLog*, Packet*);
void LogPayload(TextLog*, Packet*);
void LogNetData(TextLog*, const uint8_t* data, const int len, Packet*);

void LogDiv(TextLog*);
void LogTimeStamp(TextLog*, Packet*);

void LogTrHeader(TextLog*, Packet*);
void Log2ndHeader(TextLog*, Packet*);
void LogIpAddrs(TextLog*, Packet*);

void LogIPHeader(TextLog*, Packet*);
void LogTCPHeader(TextLog*, Packet*);
void LogUDPHeader(TextLog*, Packet*);
void LogICMPHeader(TextLog*, Packet*);

SO_PUBLIC void LogIpOptions(TextLog*, const IP4Hdr*, uint16_t valid_ip4_len);
SO_PUBLIC void LogTcpOptions(TextLog*, const tcp::TCPHdr*, uint16_t valid_tcp_len);

#endif

