//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
// nhttp_event_gen.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_EVENT_GEN_H
#define NHTTP_EVENT_GEN_H

#include <assert.h>

#include "events/event_queue.h"

#include "nhttp_enum.h"

//-------------------------------------------------------------------------
// Event generator class
//-------------------------------------------------------------------------

class NHttpEventGen
{
public:
    void reset() { events_generated = 0; }
    void create_event(NHttpEnums::EventSid sid)
    {
        assert(((int)sid > 0) && ((int)sid <= 64));
        if ((events_generated & (((uint64_t)1) << (sid-1))) == 0)
        {
            SnortEventqAdd(NHttpEnums::NHTTP_GID, (uint32_t)sid);
            events_generated |= (((uint64_t)1) << (sid-1));
        }
    }

    // The following method is for convenience of debug and test output only! The 64-bit
    // implementation will not be big enough forever and this interface cannot be all over the
    // code.
    uint64_t get_raw() const { return events_generated; }

private:
    uint64_t events_generated = 0;
};

#endif

