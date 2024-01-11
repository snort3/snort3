//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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
// http_buffer_info.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "http_buffer_info.h"

#include "hash/hash_key_operations.h"
#include "http_enum.h"

using namespace snort;
using namespace HttpEnums;

uint32_t HttpBufferInfo::hash() const
{
    uint32_t a = type;
    uint32_t b = sub_id >> 32;
    uint32_t c = sub_id & 0xFFFFFFFF;
    uint32_t d = form >> 32;
    uint32_t e = form & 0xFFFFFFFF;
    mix(a,b,c);
    mix(d,e,a);
    finalize(d,e,a);
    return d;
}

bool HttpBufferInfo::operator==(const HttpBufferInfo& rhs) const
{
    return (type == rhs.type &&
         sub_id == rhs.sub_id &&
         form == rhs.form);
}

bool HttpBufferInfo::is_request() const
{
    return ((form & FORM_REQUEST) != 0);
}
