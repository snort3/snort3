//--------------------------------------------------------------------------
// Copyright (C) 2021-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/data_bus.h"
#include "service_inspectors/ssh/ssh_types.h"

struct  SshEventIds { enum : unsigned { STATE_CHANGE, ALGORITHM, num_ids }; };

const snort::PubKey ssh_pub_key { "ssh", SshEventIds::num_ids };

enum SshEventType
{
    SSH_VERSION_STRING,
    SSH_VALIDATION
};

enum SshValidationResult
{
    SSH_NOT_FINISHED,
    SSH_VALID_KEXINIT,
    SSH_INVALID_VERSION,
    SSH_INVALID_KEXINIT
};

class SO_PUBLIC SshEvent : public snort::DataEvent
{
public:
    SshEvent(const SshEventType event_type, const SshValidationResult result,
        const std::string& version_str, const uint8_t direction,
        const snort::Packet* packet, const char* login_direction, uint8_t ssh_version) :
        event_type(event_type), result(result), version_str(version_str),
        direction(direction), packet(packet), login_direction(login_direction),
        ssh_version(ssh_version)
        { }

    SshEventType get_event_type() const;
    SshValidationResult get_validation_result() const;
    const std::string& get_version_str() const;
    uint8_t get_direction() const;
    const snort::Packet* get_packet() const override;
    const char* get_login_direction() const;
    uint8_t get_ssh_version() const;

private:
    const SshEventType event_type;
    const SshValidationResult result;
    const std::string version_str;
    const uint8_t direction;
    const snort::Packet* packet;
    const char* login_direction;
    const uint8_t ssh_version;
};

class SO_PUBLIC SshAlgoEvent : public snort::DataEvent
{
public:
    union Algorithms
    {
        struct
        {
            const char* kex_algorithms;
            const char* server_host_key_algorithms;
            const char* encryption_algorithms_client_to_server;
            const char* encryption_algorithms_server_to_client;
            const char* mac_algorithms_client_to_server;
            const char* mac_algorithms_server_to_client;
            const char* compression_algorithms_client_to_server;
            const char* compression_algorithms_server_to_client;
        } named;
        const char* unnamed[NUM_KEXINIT_LISTS];
    };

    SshAlgoEvent(const Algorithms& algos, uint8_t dir) : algos(algos), direction(dir)
    { }

    const char* get_kex_algorithms() const;
    const char* get_server_host_key_algorithms() const;
    const char* get_encryption_algorithms_client_to_server() const;
    const char* get_encryption_algorithms_server_to_client() const;
    const char* get_mac_algorithms_client_to_server() const;
    const char* get_mac_algorithms_server_to_client() const;
    const char* get_compression_algorithms_client_to_server() const;
    const char* get_compression_algorithms_server_to_client() const;
    uint8_t get_direction() const;

private:
    const Algorithms& algos;
    uint8_t direction;
};

#endif
