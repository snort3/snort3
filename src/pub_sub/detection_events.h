//--------------------------------------------------------------------------
// Copyright (C) 2025 Cisco and/or its affiliates. All rights reserved.
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
// detection_events.h author Anna Norokh <anorokh@cisco.com>

#ifndef DETECTION_EVENTS_H
#define DETECTION_EVENTS_H

#include "events/event.h"
#include "framework/data_bus.h"
#include "protocols/packet.h"

namespace snort
{

struct DetectionEventIds
{
    enum : unsigned
    {
        IPS_LOGGING,     // before IPS loggers invoked
        CONTEXT_LOGGING, // in an IPS logger
        BUILTIN,         // built-in event added in the event queue
        MAX
    };
};

const PubKey de_pub_key { "detection", DetectionEventIds::MAX };

class IpsRuleEvent : public DataEvent, public Event
{
public:
    IpsRuleEvent(const Event& e) : Event(e) {}
    ~IpsRuleEvent() override
    {
        for (const char* ref : references)
            delete[] ref;
    }

    const std::string& get_stripped_msg() const;

    const std::vector<const char*>& get_references() const;

protected:
    mutable std::vector<const char*> references;

private:
    mutable std::string stripped_msg;
};

class IpsQueuingEvent : public DataEvent, public Event
{
public:
    IpsQueuingEvent(const SigInfo& sig_info) : Event(0, 0, sig_info, nullptr, "") {}

    const std::string& get_stripped_msg() const;

private:
    mutable std::string stripped_msg;
};

}
#endif
