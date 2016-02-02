//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "event.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "main/snort_config.h"
#include "detection/signature.h"

THREAD_LOCAL uint16_t event_id; // FIXIT-M also incremented in fpLogEvent()
THREAD_LOCAL SigInfo sig_info;  // FIXIT-M move to stack

void SetEvent(
    Event* event, uint32_t generator, uint32_t id, uint32_t rev,
    uint32_t classification, uint32_t priority, uint32_t event_ref)
{
    sig_info.generator = generator;
    sig_info.id = id;
    sig_info.rev = rev;
    sig_info.class_id = classification;
    sig_info.priority = priority;

    event->sig_info = &sig_info;
    /* this one gets set automatically */
    event->event_id = ++event_id | SnortConfig::get_event_log_id();

    if (event_ref)
        event->event_reference = event_ref;
    else
        event->event_reference = event->event_id;

    event->ref_time.tv_sec = event->ref_time.tv_usec = 0;
}

