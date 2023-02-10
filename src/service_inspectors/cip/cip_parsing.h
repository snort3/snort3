//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// cip_parsing.h author RA/Cisco

/* Description: Data parsing for EtherNet/IP and CIP formats. */

#ifndef CIP_PARSING_H
#define CIP_PARSING_H

#include <cstdint>
#include <cstring>
#include "pub_sub/cip_events.h"       // For CipEventData

#include "cip_definitions.h"  // For CIP structs

namespace snort
{
struct Packet;
}

//// EtherNet/IP Parsing

// Constants - EtherNet/IP encapsulation layer
#define ENIP_HEADER_SIZE 24u

// EtherNet/IP commands.
enum EnipCommand
{
    ENIP_COMMAND_NOP = 0x0000,
    ENIP_COMMAND_LIST_SERVICES = 0x0004,
    ENIP_COMMAND_LIST_IDENTITY = 0x0063,
    ENIP_COMMAND_LIST_INTERFACES = 0x0064,
    ENIP_COMMAND_REGISTER_SESSION = 0x0065,
    ENIP_COMMAND_UNREGISTER_SESSION = 0x0066,
    ENIP_COMMAND_SEND_RR_DATA = 0x006F,
    ENIP_COMMAND_SEND_UNIT_DATA = 0x0070
};

/// EtherNet/IP data parsing functions.
bool parse_enip_layer(const uint8_t* data,
    size_t data_length,
    bool is_TCP,
    CipCurrentData* current_data,
    CipGlobalSessionData* global_data);

void pack_cip_request_event(const CipRequest* request, CipEventData* cip_event_data);

#endif  // CIP_PARSING_H

