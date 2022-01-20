//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

using namespace snort;

static THREAD_LOCAL uint16_t g_event_id;

uint16_t get_event_id()
{
    return g_event_id;
}

void incr_event_id()
{
    g_event_id++;
}

static uint32_t calc_event_id(uint16_t id, uint16_t log_id)
{
    // Use instance ID to make log_id unique per packet thread. Even if
    // it overflows, value will still be unique if there are less than
    // 65k threads.
    log_id += snort::get_instance_id();
    return (id | (log_id << 16));
}

void Event::update_event_id(uint16_t log_id)
{
    event_id = calc_event_id(g_event_id, log_id);
}

void Event::update_event_id_and_ref(uint16_t log_id)
{
    event_id = calc_event_id(g_event_id, log_id);
    event_reference = event_id;
}

void Event::set_event(uint32_t gid, uint32_t sid, uint32_t rev,
    uint32_t classification, uint32_t priority, uint16_t event_ref,
    uint16_t log_id, const struct timeval& tv)
{
    sig_info->gid = gid;
    sig_info->sid = sid;
    sig_info->rev = rev;
    sig_info->class_id = classification;
    sig_info->priority = priority;

    /* update event_id based on g_event_id. */
    incr_event_id();
    update_event_id(SnortConfig::get_conf()->get_event_log_id());

    if (event_ref)
        event_reference = calc_event_id(event_ref, log_id);
    else
        event_reference = event_id;

    ref_time.tv_sec = tv.tv_sec;
    ref_time.tv_usec = tv.tv_usec;
}

