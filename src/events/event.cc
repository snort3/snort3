//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
#include "main/thread.h"

using namespace snort;

static THREAD_LOCAL uint16_t g_event_id;
static SigInfo s_dummy;

static uint32_t calc_event_id(uint16_t id)
{
    // Use instance ID to make log_id unique per packet thread. Even if
    // it overflows, value will still be unique if there are less than
    // 65k threads.
    uint16_t log_id = SnortConfig::get_conf()->get_event_log_id();
    log_id += snort::get_instance_id();
    return (id | (log_id << 16));
}

uint16_t Event::get_curr_seq_num()
{ return g_event_id; }

uint16_t Event::get_next_seq_num()
{ return ++g_event_id; }

uint32_t Event::get_next_event_id()
{
    uint16_t eseq = get_next_seq_num();
    return calc_event_id(eseq);
}

Event::Event() : sig_info(s_dummy) { }

Event::Event(uint32_t sec, uint32_t usec, const SigInfo& si, const char** bufs, const char* act) :
    sig_info(si)
{
    ts_sec = sec;
    ts_usec = usec;

    buffs_to_dump = bufs;
    action = act;

    event_id = calc_event_id(g_event_id);
    event_reference = event_id;
}

Event::Event(uint32_t sec, uint32_t usec, const SigInfo& si, const char** bufs, const char* act, uint32_t ref) :
    sig_info(si)
{
    ts_sec = sec;
    ts_usec = usec;

    buffs_to_dump = bufs;
    action = act;

    event_id = get_next_event_id();
    event_reference = calc_event_id(ref);
}

uint32_t Event::get_seconds() const
{ return ts_sec; }

void Event::get_timestamp(uint32_t& sec, uint32_t& usec) const
{ sec = ts_sec; usec = ts_usec; }

uint32_t Event::get_event_id() const
{ return event_id; }

uint32_t Event::get_event_reference() const
{ return event_reference; }

uint32_t Event::get_gid() const
{ return sig_info.gid; }

uint32_t Event::get_sid() const
{ return sig_info.sid; }

uint32_t Event::get_rev() const
{ return sig_info.rev; }

void Event::get_sig_ids(uint32_t& gid, uint32_t& sid, uint32_t& rev) const
{
    gid = sig_info.gid;
    sid = sig_info.sid;
    rev = sig_info.rev;
}

const char* Event::get_msg() const
{
    if ( sig_info.message.empty() )
        return nullptr;

    return sig_info.message.c_str();
}

const char* Event::get_class_type() const
{
    if ( !sig_info.class_type or sig_info.class_type->text.empty() )
        return nullptr;

    return sig_info.class_type->text.c_str();
}

const char** Event::get_buffers() const
{ return buffs_to_dump; }

const char* Event::get_action() const
{ return action; }

uint32_t Event::get_class_id() const
{ return sig_info.class_id; }

uint32_t Event::get_priority() const
{ return sig_info.priority; }

bool Event::get_target(bool& src) const
{
    if ( sig_info.target == TARGET_SRC )
    {
        src = true;
        return true;
    }
    else if ( sig_info.target == TARGET_DST )
    {
        src = false;
        return true;
    }
    return false;
}

bool Event::get_reference(unsigned idx, const char*& name, const char*& id, const char*& url) const
{
    if ( idx >= sig_info.refs.size() )
        return false;

    name = sig_info.refs[idx]->system->name.c_str();
    id = sig_info.refs[idx]->id.c_str();

    auto* ref = reference_system_lookup(SnortConfig::get_conf(), sig_info.refs[idx]->system->name);
    url = (ref ? ref->url.c_str() : nullptr);

    return true;
}

