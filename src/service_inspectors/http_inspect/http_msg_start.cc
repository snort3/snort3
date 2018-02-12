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
// http_msg_start.cc author Tom Peters <thopeter@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_msg_start.h"

using namespace HttpEnums;

void HttpMsgStart::analyze()
{
    start_line.set(msg_text);
    parse_start_line();
}

void HttpMsgStart::derive_version_id()
{
    if (version.start()[6] != '.')
    {
        version_id = VERS__PROBLEMATIC;
        add_infraction(INF_BAD_VERSION);
        create_event(EVENT_BAD_VERS);
    }
    else if ((version.start()[5] == '1') && (version.start()[7] == '1'))
    {
        version_id = VERS_1_1;
    }
    else if ((version.start()[5] == '1') && (version.start()[7] == '0'))
    {
        version_id = VERS_1_0;
    }
    else if ((version.start()[5] == '2') && (version.start()[7] == '0'))
    {
        version_id = VERS_2_0;
    }
    else if ((version.start()[5] == '0') && (version.start()[7] == '9'))
    {
        // Real 0.9 traffic would never be labeled HTTP/0.9 because 0.9 is older than the version
        // system. Aside from the possibility that someone might do this to make trouble,
        // HttpStreamSplitter::reassemble() converts 0.9 responses to a simple form of 1.0 format
        // to allow us to process 0.9 without a lot of extra development. Such responses are
        // labeled 0.9.
        // FIXIT-M the 0.9 trick opens the door to someone spoofing us with a real start line
        // labeled HTTP/0.9. Need to close this weakness.
        // FIXIT-M similarly is "HTTP/2.0" a legitimate thing we could actually see? Or would real
        // HTTP 2.0 traffic not look like that? Possibly relabeled 1.1 by the down conversion
        // software. Need to research and resolve this issue.
        version_id = VERS_0_9;
    }
    else if ((version.start()[5] >= '0') && (version.start()[5] <= '9') &&
        (version.start()[7] >= '0') && (version.start()[7] <= '9'))
    {
        version_id = VERS__OTHER;
        add_infraction(INF_UNKNOWN_VERSION);
        create_event(EVENT_UNKNOWN_VERS);
    }
    else
    {
        version_id = VERS__PROBLEMATIC;
        add_infraction(INF_BAD_VERSION);
        create_event(EVENT_BAD_VERS);
    }
}

