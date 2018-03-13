//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include <cstdio>

#include "main/snort_types.h"

namespace snort
{
namespace tcp { struct TCPHdr; }
struct Packet;

SO_PUBLIC void CreateTCPFlagString(const tcp::TCPHdr* const, char*);
}

FILE* OpenAlertFile(const char*);
int RollAlertFile(const char*);

void OpenLogger();
void CloseLogger();
void LogIPPkt(snort::Packet*);
void LogFlow(snort::Packet*);
void LogNetData(const uint8_t* data, const int len, snort::Packet*);

#endif

