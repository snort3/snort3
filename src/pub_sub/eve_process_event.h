//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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
// eve_process_event.h author Cliff Judge <cljudge@cisco.com>

#ifndef EVE_PROCESS_EVENT_H
#define EVE_PROCESS_EVENT_H

#include <string>
#include "framework/data_bus.h"

#define EVE_PROCESS_EVENT "eve_process_event"

class EveProcessEvent : public snort::DataEvent
{
public:
    EveProcessEvent(const snort::Packet& p, const char* process, uint8_t process_conf) :
        p(p), process_name(process), process_confidence(process_conf) { }

    EveProcessEvent(const snort::Packet& p, const char* server) : p(p), server_name(server) { }

    const snort::Packet* get_packet() override { return &p; }

    const std::string& get_process_name() const
    {
        return process_name;
    }

    uint8_t get_process_confidence() const
    {
        return process_confidence;
    }

    const std::string& get_server_name() const
    {
        return server_name;
    }

    void set_server_name(const char* server)
    {
        if (server)
            server_name = server;
    }

private:
    const snort::Packet &p;
    std::string process_name;
    uint8_t process_confidence = 0;
    std::string server_name;
};

#endif
