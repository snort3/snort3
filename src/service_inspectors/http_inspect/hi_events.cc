//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
// hi_events.cc author Russ Combs <rucombs@cisco.com>

#include "hi_events.h"

#include <assert.h>
#include <strings.h>

#include "events/event_queue.h"

static THREAD_LOCAL uint64_t gid_client = 0;
static THREAD_LOCAL uint64_t gid_server = 0;

static inline void set(uint64_t& mask, unsigned sid)
{
    assert(sid && sid < 64);
    mask |= (1 << (sid-1));
}

static void queue(unsigned gid, uint64_t mask)
{
    int sid;

    while ( (sid = ffs(mask)) )
    {
        SnortEventqAdd(gid, sid);
        mask ^= (1 << (sid-1));
    }
}

void hi_set_event(unsigned gid, unsigned sid)
{
    switch ( gid )
    {
    case GID_HTTP_CLIENT:
        set(gid_client, sid);
        break;

    case GID_HTTP_SERVER:
        set(gid_server, sid);
        break;

    default:
        assert(false);
    }
}

void hi_clear_events()
{
    gid_client = gid_server = 0;
}

void hi_queue_events()
{
    if ( gid_client )
        queue(GID_HTTP_CLIENT, gid_client);

    if ( gid_server )
        queue(GID_HTTP_SERVER, gid_server);
}

