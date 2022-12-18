//--------------------------------------------------------------------------
// Copyright (C) 2022-2022 Cisco and/or its affiliates. All rights reserved.
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
// reputation_events.h author Ron Dempster <rdempste@cisco.com>

#ifndef REPUTATION_EVENTS_H
#define REPUTATION_EVENTS_H

#include "framework/data_bus.h"

namespace snort
{

struct ReputationEventIds { enum : unsigned { REP_MATCHED, num_ids }; };

const PubKey reputation_pub_key { "reputation", ReputationEventIds::num_ids };

enum ReputationVerdict
{
    REP_VERDICT_BLOCKED,
    REP_VERDICT_TRUSTED,
    REP_VERDICT_MONITORED
};

class ReputationVerdictEvent : public DataEvent
{
public:
    ReputationVerdictEvent(const Packet* packet, ReputationVerdict verdict, uint32_t list_id, bool source_matched)
        : packet(packet), verdict(verdict), list_id(list_id), source_matched(source_matched)
    { }

    const Packet* get_packet() const override
    { return packet; }

    ReputationVerdict get_verdict() const
    { return verdict; }

    uint32_t get_list_id() const
    { return list_id; }

    bool get_source_matched() const
    { return source_matched; }

private:
    const Packet* packet;
    ReputationVerdict verdict;
    uint32_t list_id;
    bool source_matched;
};

}

#endif
