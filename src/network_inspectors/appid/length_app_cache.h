//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// length_app_cache.h author Sourcefire Inc.

#ifndef LENGTH_APP_CACHE_H
#define LENGTH_APP_CACHE_H

#include "application_ids.h"
#include "protocols/protocol_ids.h"

#define LENGTH_SEQUENCE_CNT_MAX (5)

#pragma pack(1)

class AppIdConfig;
enum class IpProtocol : uint8_t;

struct LengthSequenceEntry
{
    uint8_t direction = 0;     /* APP_ID_FROM_INITIATOR or APP_ID_FROM_RESPONDER */
    uint16_t length = 0;       /* payload size (bytes) */
};

struct LengthKey
{
    IpProtocol proto = IpProtocol::PROTO_NOT_SET;  // IpProtocol::TCP or IpProtocol::UDP
    uint8_t sequence_cnt = 0;                      // num valid entries in sequence
    LengthSequenceEntry sequence[LENGTH_SEQUENCE_CNT_MAX];
};

#pragma pack()

void init_length_app_cache();
void free_length_app_cache();
AppId find_length_app_cache(const LengthKey*);
bool add_length_app_cache(const LengthKey*, AppId);

#endif

