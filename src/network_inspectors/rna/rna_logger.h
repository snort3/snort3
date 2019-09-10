//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

#ifndef RNA_LOGGER_H
#define RNA_LOGGER_H

#include "events/event.h"
#include "host_tracker/host_cache.h"

namespace snort
{
class Flow;
struct Packet;
}

using RnaTracker = std::shared_ptr<snort::HostTracker>;

struct RnaLoggerEvent : public Event
{
    RnaLoggerEvent(uint16_t p_type, uint16_t p_subtype, const RnaTracker* p_ht,
        const u_int8_t* p_mac) : type(p_type), subtype(p_subtype), ht(p_ht), mac(p_mac) { }
    uint16_t type;
    uint16_t subtype;
    const RnaTracker* ht;
    const u_int8_t* mac;
    const struct in6_addr* ip;
    void* cond_var = nullptr;
};

class RnaLogger
{
public:
    RnaLogger(const bool enable) : enabled(enable) { }
    bool log(uint16_t type, uint16_t subtype, const snort::Packet* p, RnaTracker* ht,
       const struct in6_addr* src_ip, const u_int8_t* src_mac,
       uint32_t event_time = 0, void* cond_var = nullptr);

private:
    const bool enabled;
};

#endif
