//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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

#ifndef MCP_DETECTION_EVENT_H
#define MCP_DETECTION_EVENT_H

#include <cstdint>
#include <string>

#include "framework/data_bus.h"
#include "pub_sub/external_event_ids.h"

class McpDetectionEvent : public snort::DataEvent
{
public:
    McpDetectionEvent(const snort::Packet& packet, int64_t stream_id, const char* method)
        : packet(packet), stream_id(stream_id),
          method(method ? method : "") { }

    const snort::Packet* get_packet() const override
    { return &packet; }

    int64_t get_stream_id() const
    { return stream_id; }

    bool is_httpx() const
    { return stream_id >= 0; }

    const std::string& get_method() const
    { return method; }

private:
    const snort::Packet& packet;
    int64_t stream_id;
    std::string method;
};

#endif
