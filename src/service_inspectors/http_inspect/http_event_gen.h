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
// http_event_gen.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_EVENT_GEN_H
#define HTTP_EVENT_GEN_H

#include <bitset>
#include <cassert>

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "utils/util_cstring.h"

#include "http_enum.h"

//-------------------------------------------------------------------------
// Event generator class
//-------------------------------------------------------------------------

class HttpEventGen
{
public:
    virtual ~HttpEventGen() = default;

    virtual void create_event(int sid)
    {
        if (sid == HttpEnums::EVENT__NONE)
            return;
        assert((sid > 0) && (sid <= MAX));
        if (!events_generated[sid-1])
        {
            snort::DetectionEngine::queue_event(HttpEnums::HTTP_GID, (uint32_t)sid);
            events_generated[sid-1] = true;
        }
    }

    void generate_misformatted_http(const uint8_t* buffer, uint32_t length)
    {
        if ( snort::SnortStrnStr((const char*)buffer, length, "HTTP/") != nullptr )
            create_event(HttpEnums::EVENT_MISFORMATTED_HTTP);
        else
            create_event(HttpEnums::EVENT_LOSS_OF_SYNC);
    }

    // The following methods are for convenience of debug and test output only!
    uint64_t get_raw() const { return
       (events_generated & std::bitset<MAX>(0xFFFFFFFFFFFFFFFF)).to_ulong(); }
    uint64_t get_raw2() const { return
       ((events_generated >> BASE_1XX_EVENTS) & std::bitset<MAX>(0xFFFFFFFFFFFFFFFF)).to_ulong(); }
    uint64_t get_raw3() const { return
       ((events_generated >> BASE_2XX_EVENTS) & std::bitset<MAX>(0xFFFFFFFFFFFFFFFF)).to_ulong(); }
private:
    static const unsigned BASE_1XX_EVENTS = 100;
    static const unsigned BASE_2XX_EVENTS = 200;
    static const int MAX = HttpEnums::EVENT__MAX_VALUE;
    std::bitset<MAX> events_generated = 0;
};

#endif

