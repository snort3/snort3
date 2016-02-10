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
// nhttp_msg_start.cc author Tom Peters <thopeter@cisco.com>

#include <string.h>
#include <sys/types.h>
#include <stdio.h>

#include "nhttp_enum.h"
#include "nhttp_msg_start.h"

using namespace NHttpEnums;

void NHttpMsgStart::analyze()
{
    start_line.start = msg_text.start;
    start_line.length = msg_text.length;
    parse_start_line();
    gen_events();
}

void NHttpMsgStart::derive_version_id()
{
    if (version.start[6] != '.')
    {
        version_id = VERS__PROBLEMATIC;
        infractions += INF_BAD_VERSION;
        events.create_event(EVENT_BAD_VERS);
    }
    else if ((version.start[5] == '1') && (version.start[7] == '1'))
    {
        version_id = VERS_1_1;
    }
    else if ((version.start[5] == '1') && (version.start[7] == '0'))
    {
        version_id = VERS_1_0;
    }
    else if ((version.start[5] == '2') && (version.start[7] == '0'))
    {
        version_id = VERS_2_0;
    }
    else if ((version.start[5] == '0') && (version.start[7] == '9'))
    {
        // Real 0.9 traffic would never be labeled HTTP/0.9 because 0.9 is older than the version
        // system. Aside from the possibility that someone might do this to make trouble,
        // NHttpStreamSplitter::reassemble() converts 0.9 responses to a simple form of 1.0 format
        // to allow us to process 0.9 without a lot of extra development. Such responses are
        // labeled 0.9.
        version_id = VERS_0_9;
    }
    else if ((version.start[5] >= '0') && (version.start[5] <= '9') &&
        (version.start[7] >= '0') && (version.start[7] <= '9'))
    {
        version_id = VERS__OTHER;
        infractions += INF_UNKNOWN_VERSION;
        events.create_event(EVENT_UNKNOWN_VERS);
    }
    else
    {
        version_id = VERS__PROBLEMATIC;
        infractions += INF_BAD_VERSION;
        events.create_event(EVENT_BAD_VERS);
    }
}

