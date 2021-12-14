//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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
// ssh_events.h author Daniel McGarvey <danmcgar@cisco.com>

#ifndef SSH_EVENTS_H
#define SSH_EVENTS_H

// This event allows the SSH service inspector to publish extracted metadata
// for use by data bus subscribers

#include "service_inspectors/ssh/ssh.h"

#define SSH_EVENT "ssh_event"

enum SshEventType {
    SSH_VERSION_STRING,
    SSH_VALIDATION
};

enum SshValidationResult {
    SSH_NOT_FINISHED,
    SSH_VALID_KEXINIT,
    SSH_INVALID_VERSION,
    SSH_INVALID_KEXINIT
};

class SshEvent : public snort::DataEvent
{
public:
    SshEvent(const SshEventType event_type, const SshValidationResult result,
        const std::string& version_str, const uint8_t direction, const snort::Packet* packet) :
        event_type(event_type), result(result), version_str(version_str), direction(direction), packet(packet)
        { }

    SshEventType get_event_type() const
    { return event_type; }

    SshValidationResult get_validation_result() const
    { return result; }

    const std::string& get_version_str() const
    { return version_str; }

    uint8_t get_direction() const
    { return direction; }

    const snort::Packet* get_packet() override
    { return packet; }

private:
    const SshEventType event_type;
    const SshValidationResult result;
    const std::string version_str;
    const uint8_t direction;
    const snort::Packet* packet;
};

#endif
