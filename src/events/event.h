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

#ifndef EVENT_H
#define EVENT_H

#include "main/thread.h"

struct SigInfo;
extern THREAD_LOCAL uint16_t event_id;

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
    uint32_t event_id = 0;
    uint32_t event_reference = 0; // reference to other events that have gone off,
                              // such as in the case of tagged packets...
    struct sf_timeval32 ref_time = { 0, 0 };   /* reference time for the event reference */
    const char* alt_msg = nullptr;

    Event() = default;
    Event(SigInfo& si)
    { sig_info = &si; }
};

void SetEvent(
    Event&, uint32_t gid, uint32_t sid, uint32_t rev,
    uint32_t classification, uint32_t priority, uint32_t event_ref);

#endif

