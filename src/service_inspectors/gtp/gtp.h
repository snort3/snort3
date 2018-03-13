//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
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

// gtp.h author Hui Cao <hcao@sourcefire.com>

#ifndef GTP_H
#define GTP_H

// Provides convenience functions for parsing and querying configuration.

#include <string>

#include "framework/counts.h"
#include "main/thread.h"

namespace snort
{
struct Packet;
}

#define MIN_GTP_VERSION_CODE   (0)
#define MAX_GTP_VERSION_CODE   (2)

#define MIN_GTP_TYPE_CODE      (0)
#define MAX_GTP_TYPE_CODE      (255)

#define MIN_GTP_IE_CODE        (0)
#define MAX_GTP_IE_CODE        (255)

struct GTP_MsgType
{
    std::string name;
};

struct GTP_InfoElement
{
    std::string name;
    uint16_t length; // 0 for variable length
};

struct GTPConfig
{
    GTP_MsgType msgv[MAX_GTP_VERSION_CODE + 1][MAX_GTP_TYPE_CODE + 1];
    GTP_InfoElement infov[MAX_GTP_VERSION_CODE + 1][MAX_GTP_IE_CODE + 1];
};

struct GTP_Stats
{
    PegCount sessions;
    PegCount concurrent_sessions;
    PegCount max_concurrent_sessions;
    PegCount events;
    PegCount unknownTypes;
    PegCount unknownIEs;

    // FIXIT-L add these stats
    //PegCount messages[MAX_GTP_VERSION_CODE + 1][MAX_GTP_TYPE_CODE + 1];

    // FIXIT-L can't put non-pegs in stats; why is this here?
    //GTP_MsgType* msgTypeTable[MAX_GTP_VERSION_CODE + 1][MAX_GTP_TYPE_CODE + 1];
};

extern THREAD_LOCAL GTP_Stats gtp_stats;

void GTPmain(const GTPConfig&, snort::Packet*);

#endif

