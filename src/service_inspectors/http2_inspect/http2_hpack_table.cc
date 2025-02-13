//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
// http2_hpack_table.cc author Katura Harvey <katharve@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http2_enum.h"
#include "http2_flow_data.h"
#include "http2_hpack_table.h"

#include <cstring>

#define MAKE_TABLE_ENTRY(name, value) \
    HpackTableEntry(strlen(name), (const uint8_t*)name, strlen(value), (const uint8_t*)value)

using namespace Http2Enums;

HpackTableEntry::HpackTableEntry(const Field& copy_name, const Field& copy_value)
{
    uint8_t* new_name = new uint8_t[copy_name.length()];
    uint8_t* new_value = new uint8_t[copy_value.length()];
    memcpy(new_name, copy_name.start(), copy_name.length());
    memcpy(new_value, copy_value.start(), copy_value.length());

    name.set(copy_name.length(), new_name, true);
    value.set(copy_value.length(), new_value, true);
}

const HpackTableEntry HpackIndexTable::static_table[STATIC_MAX_INDEX + 1] =
{
    MAKE_TABLE_ENTRY("", ""),
    MAKE_TABLE_ENTRY(":authority", ""),
    MAKE_TABLE_ENTRY(":method", "GET"),
    MAKE_TABLE_ENTRY(":method", "POST"),
    MAKE_TABLE_ENTRY(":path", "/"),
    MAKE_TABLE_ENTRY(":path", "/index.html"),
    MAKE_TABLE_ENTRY(":scheme", "http"),
    MAKE_TABLE_ENTRY(":scheme", "https"),
    MAKE_TABLE_ENTRY(":status", "200"),
    MAKE_TABLE_ENTRY(":status", "204"),
    MAKE_TABLE_ENTRY(":status", "206"),
    MAKE_TABLE_ENTRY(":status", "304"),
    MAKE_TABLE_ENTRY(":status", "400"),
    MAKE_TABLE_ENTRY(":status", "404"),
    MAKE_TABLE_ENTRY(":status", "500"),
    MAKE_TABLE_ENTRY("accept-charset", ""),
    MAKE_TABLE_ENTRY("accept-encoding", "gzip, deflate"),
    MAKE_TABLE_ENTRY("accept-language", ""),
    MAKE_TABLE_ENTRY("accept-ranges", ""),
    MAKE_TABLE_ENTRY("accept", ""),
    MAKE_TABLE_ENTRY("access-control-allow-origin", ""),
    MAKE_TABLE_ENTRY("age", ""),
    MAKE_TABLE_ENTRY("allow", ""),
    MAKE_TABLE_ENTRY("authorization", ""),
    MAKE_TABLE_ENTRY("cache-control", ""),
    MAKE_TABLE_ENTRY("content-disposition", ""),
    MAKE_TABLE_ENTRY("content-encoding", ""),
    MAKE_TABLE_ENTRY("content-language", ""),
    MAKE_TABLE_ENTRY("content-length", ""),
    MAKE_TABLE_ENTRY("content-location", ""),
    MAKE_TABLE_ENTRY("content-range", ""),
    MAKE_TABLE_ENTRY("content-type", ""),
    MAKE_TABLE_ENTRY("cookie", ""),
    MAKE_TABLE_ENTRY("date", ""),
    MAKE_TABLE_ENTRY("etag", ""),
    MAKE_TABLE_ENTRY("expect", ""),
    MAKE_TABLE_ENTRY("expires", ""),
    MAKE_TABLE_ENTRY("from", ""),
    MAKE_TABLE_ENTRY("host", ""),
    MAKE_TABLE_ENTRY("if-match", ""),
    MAKE_TABLE_ENTRY("if-modified-since", ""),
    MAKE_TABLE_ENTRY("if-none-match", ""),
    MAKE_TABLE_ENTRY("if-range", ""),
    MAKE_TABLE_ENTRY("if-unmodified-since", ""),
    MAKE_TABLE_ENTRY("last-modified", ""),
    MAKE_TABLE_ENTRY("link", ""),
    MAKE_TABLE_ENTRY("location", ""),
    MAKE_TABLE_ENTRY("max-forwards", ""),
    MAKE_TABLE_ENTRY("proxy-authenticate", ""),
    MAKE_TABLE_ENTRY("proxy-authorization", ""),
    MAKE_TABLE_ENTRY("range", ""),
    MAKE_TABLE_ENTRY("referer", ""),
    MAKE_TABLE_ENTRY("refresh", ""),
    MAKE_TABLE_ENTRY("retry-after", ""),
    MAKE_TABLE_ENTRY("server", ""),
    MAKE_TABLE_ENTRY("set-cookie", ""),
    MAKE_TABLE_ENTRY("strict-transport-security", ""),
    MAKE_TABLE_ENTRY("transfer-encoding", ""),
    MAKE_TABLE_ENTRY("user-agent", ""),
    MAKE_TABLE_ENTRY("vary", ""),
    MAKE_TABLE_ENTRY("via", ""),
    MAKE_TABLE_ENTRY("www-authenticate", ""),
};

const HpackTableEntry* HpackIndexTable::lookup(uint64_t index) const
{
    if (index <= STATIC_MAX_INDEX)
        return &static_table[index];
    else
        return dynamic_table.get_entry(index);
}

bool HpackIndexTable::add_index(const Field& name, const Field& value)
{
    return dynamic_table.add_entry(name, value);
}
