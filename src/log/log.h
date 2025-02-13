//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef LOG_H
#define LOG_H

// this is for legacy logging like stream_ip debug and stream_tcp show rebuilt.
// it should not be used for new code. existing uses should be converted to the
// trace logger system or directly call TextLog which this wraps.

#include <cstdio>

#include "main/snort_types.h"

namespace snort
{
    struct Packet;
}

FILE* OpenAlertFile(const char*, bool is_critical=true);
int RollAlertFile(const char*);

void OpenLogger();
void CloseLogger();
void LogIPPkt(snort::Packet*);
void LogFlow(snort::Packet*);
void LogNetData(const uint8_t* data, const int len, snort::Packet*);

void InitProtoNames();
void CleanupProtoNames();

const char* get_protocol_name(uint8_t ip_proto);

#endif

