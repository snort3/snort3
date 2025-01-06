//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_types.h"

struct SigInfo;

class SO_PUBLIC Event
{
public:
    Event();
    Event(uint32_t sec, uint32_t usec, const SigInfo&, const char** buffers, const char* action);
    Event(uint32_t sec, uint32_t usec, const SigInfo&, const char** buffers, const char* action, uint32_t ref);

    static uint16_t get_curr_seq_num();
    static uint16_t get_next_seq_num();
    static uint32_t get_next_event_id();

    uint32_t get_seconds() const;
    void get_timestamp(uint32_t& sec, uint32_t& usec) const;

    uint32_t get_event_id() const;
    uint32_t get_event_reference() const;

    const char** get_buffers() const;
    const char* get_action() const;

    uint32_t get_gid() const;
    uint32_t get_sid() const;
    uint32_t get_rev() const;

    void get_sig_ids(uint32_t& gid, uint32_t& sid, uint32_t& rev) const;

    const char* get_msg() const;
    const char* get_class_type() const;

    uint32_t get_class_id() const;
    uint32_t get_priority() const;

    // start at idx 0 and increment while true to get all refs
    bool get_reference(unsigned idx, const char*& name, const char*& id, const char*& url) const;

    // returns false if not specified; otherwise src indicates target is source or dest
    bool get_target(bool& src) const;

private:
    const SigInfo& sig_info;
    const char* action = nullptr;
    const char** buffs_to_dump = nullptr;

    uint32_t ts_sec = 0;
    uint32_t ts_usec = 0;

    uint32_t event_id = 0;
    uint32_t event_reference = 0; // reference to other events that have gone off,
                                  // such as in the case of tagged packets...
};

#endif

