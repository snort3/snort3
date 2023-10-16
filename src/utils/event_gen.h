//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
// event_gen.h author Tom Peters <thopeter@cisco.com>

#ifndef EVENT_GEN_H
#define EVENT_GEN_H

#include <bitset>
#include <cassert>

#include "detection/detection_engine.h"

//-------------------------------------------------------------------------
// Event generator class
//-------------------------------------------------------------------------

template <int EVENT_MAX, int EVENT_NONE, int GID>
class EventGen
{
public:
    EventGen() = default;

    EventGen(const std::bitset<EVENT_MAX>& suppressed) : events_suppressed(suppressed) {}

    void create_event(int sid)
    {
        if (sid == EVENT_NONE)
            return;
        assert((sid > 0) && (sid <= EVENT_MAX));
        if (!events_suppressed[sid-1])
        {
            snort::DetectionEngine::queue_event(GID, (uint32_t)sid);
            events_suppressed[sid-1] = true;
#ifdef REG_TEST
            events_generated[sid-1] = true;
#endif
        }
    }

    void suppress_event(int sid)
    {
        assert((sid > 0) && (sid <= EVENT_MAX));
        events_suppressed[sid-1] = true;
    }

#ifdef REG_TEST
    bool none_found() const { return events_generated == 0; }

    uint64_t get_raw(unsigned base) const { return
        ((events_generated >> base) & bitmask).to_ulong(); }
#endif

protected:
    std::bitset<EVENT_MAX> events_suppressed = 0;

#ifdef REG_TEST
    std::bitset<EVENT_MAX> events_generated = 0;
    const std::bitset<EVENT_MAX> bitmask = 0xFFFFFFFFFFFFFFFF;
#endif
};

#endif
