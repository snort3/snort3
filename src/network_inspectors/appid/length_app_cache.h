//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "protocols/protocol_ids.h"
#include "appid_types.h"
#include "application_ids.h"

#define LENGTH_SEQUENCE_CNT_MAX (5)

#pragma pack(1)

struct LengthSequenceEntry
{
    AppidSessionDirection direction = APP_ID_FROM_INITIATOR;
    uint16_t length = 0;       /* payload size (bytes) */
};

struct LengthKey
{
    IpProtocol proto = IpProtocol::PROTO_NOT_SET;  // IpProtocol::TCP or IpProtocol::UDP
    uint8_t sequence_cnt = 0;                      // num valid entries in sequence
    LengthSequenceEntry sequence[LENGTH_SEQUENCE_CNT_MAX];

    // Used by map where LengthKey object is the key
    bool operator<(const LengthKey& right) const
    {
        if (proto < right.proto)
            return true;
        else if (right.proto < proto)
            return false;

        if (sequence_cnt < right.sequence_cnt)
            return true;
        else if (right.sequence_cnt < sequence_cnt)
            return false;

        for (uint8_t i = 0; i < LENGTH_SEQUENCE_CNT_MAX; ++i)
        {
            if (sequence[i].direction < right.sequence[i].direction)
                return true;
            else if (right.sequence[i].direction < sequence[i].direction)
                return false;

            if (sequence[i].length < right.sequence[i].length)
                return true;
            else if (right.sequence[i].length < sequence[i].length)
                return false;
        }

        return false;
    }
};

#pragma pack()

class LengthCache
{
public:
    AppId find(const LengthKey& key)
    {
        auto entry = cache.find(key);
        if (entry == cache.end())
            return APP_ID_NONE;
        else
            return entry->second;
    }

    bool add(const LengthKey& key, AppId val)
    {
        return (cache.emplace(key, val)).second == true;
    }

private:
    std::map<LengthKey, AppId>cache;
};

#endif

