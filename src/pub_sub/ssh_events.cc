//--------------------------------------------------------------------------
// Copyright (C) 2024-2026 Cisco and/or its affiliates. All rights reserved.
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
// ssh_events.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ssh_events.h"

SshEventType SshEvent::get_event_type() const
{ return event_type; }

SshValidationResult SshEvent::get_validation_result() const
{ return result; }

const std::string& SshEvent::get_version_str() const
{ return version_str; }

uint8_t SshEvent::get_direction() const
{ return direction; }

const snort::Packet* SshEvent::get_packet() const
{ return packet; }

const char* SshEvent::get_login_direction() const
{ return login_direction; }

uint8_t SshEvent::get_ssh_version() const
{ return ssh_version; }

const char* SshAlgoEvent::get_kex_algorithms() const
{ return algos.named.kex_algorithms; }

const char* SshAlgoEvent::get_server_host_key_algorithms() const
{ return algos.named.server_host_key_algorithms; }

const char* SshAlgoEvent::get_encryption_algorithms_client_to_server() const
{ return algos.named.encryption_algorithms_client_to_server; }

const char* SshAlgoEvent::get_encryption_algorithms_server_to_client() const
{ return algos.named.encryption_algorithms_server_to_client; }

const char* SshAlgoEvent::get_mac_algorithms_client_to_server() const
{ return algos.named.mac_algorithms_client_to_server; }

const char* SshAlgoEvent::get_mac_algorithms_server_to_client() const
{ return algos.named.mac_algorithms_server_to_client; }

const char* SshAlgoEvent::get_compression_algorithms_client_to_server() const
{ return algos.named.compression_algorithms_client_to_server; }

const char* SshAlgoEvent::get_compression_algorithms_server_to_client() const
{ return algos.named.compression_algorithms_server_to_client; }

uint8_t SshAlgoEvent::get_direction() const
{ return direction; }

