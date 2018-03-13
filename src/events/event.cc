//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "event.h"

#include "detection/signature.h"
#include "main/snort_config.h"

THREAD_LOCAL uint16_t event_id; // FIXIT-M also incremented in fpLogEvent()

void SetEvent(
    Event& event, uint32_t gid, uint32_t sid, uint32_t rev,
    uint32_t classification, uint32_t priority, uint32_t event_ref)
{
    event.sig_info->gid = gid;
    event.sig_info->sid = sid;
    event.sig_info->rev = rev;
    event.sig_info->class_id = classification;
    event.sig_info->priority = priority;

    /* this one gets set automatically */
    event.event_id = ++event_id | snort::SnortConfig::get_event_log_id();

    if (event_ref)
        event.event_reference = event_ref;
    else
        event.event_reference = event.event_id;

    event.ref_time.tv_sec = event.ref_time.tv_usec = 0;
}

