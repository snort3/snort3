//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifndef EVENT_H
#define EVENT_H

#include "main/thread.h"

struct SigInfo;

/* we must use fixed size of 32 bits, because on-disk
 * format of savefiles uses 32-bit tv_sec (and tv_usec)
 */
struct sf_timeval32
{
    uint32_t tv_sec;      /* seconds */
    uint32_t tv_usec;     /* microseconds */
};

struct Event
{
    SigInfo* sig_info = nullptr;
    struct sf_timeval32 ref_time = { 0, 0 };   /* reference time for the event reference */
    const char* alt_msg = nullptr;
    std::string action_string;
    const char** buffs_to_dump = nullptr;

    Event() = default;
    Event(SigInfo& si)
    { sig_info = &si; }

    uint32_t get_event_id() const { return event_id; }
    void set_event_id(uint32_t id) { event_id = id; }

    uint32_t get_event_reference() const { return event_reference; }
    void set_event_reference(uint32_t ref) { event_reference = ref; }

    void update_event_id(uint16_t log_id);
    void update_event_id_and_ref(uint16_t log_id);
    SO_PUBLIC static uint32_t update_and_get_event_id();

    void set_event(uint32_t gid, uint32_t sid, uint32_t rev,
        uint32_t classification, uint32_t priority, uint16_t event_ref,
        uint16_t log_id, const struct timeval& tv, const std::string& act = "");


private:
    uint32_t event_id = 0;
    uint32_t event_reference = 0; // reference to other events that have gone off,
                                  // such as in the case of tagged packets...
};

uint16_t get_event_id();
void incr_event_id();

#endif

