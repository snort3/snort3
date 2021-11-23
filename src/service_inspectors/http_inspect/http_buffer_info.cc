//--------------------------------------------------------------------------
// Copyright (C) 2020-2021 Cisco and/or its affiliates. All rights reserved.
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

#include "hash/hash_key_operations.h"
#include "http_buffer_info.h"

using namespace snort;

uint32_t HttpBufferInfo::hash() const
{
    uint32_t a = type;
    uint32_t b = sub_id >> 32;
    uint32_t c = sub_id & 0xFFFFFFFF;
    uint32_t d = form >> 32;
    uint32_t e = form & 0xFFFFFFFF;
    uint32_t f = 0;
    mix(a,b,c);
    if (param)
        f = param->is_nocase() ? 1 : 0;
    mix(d,e,f);
    mix(a,c,f);
    if (param)
        mix_str(a,c,f,param->c_str(),param->length());
    finalize(a,c,f);
    return f;
}

bool HttpBufferInfo::operator==(const HttpBufferInfo& rhs) const
{
    bool param_match = false;

    if (param && rhs.param)
    {
        HttpParam& lhs_param = *param;
        HttpParam& rhs_param = *rhs.param;

        param_match = (lhs_param == rhs_param);
    }
    else if (!param && !rhs.param)
    {
        param_match = true;
    }

    return type == rhs.type &&
        sub_id == rhs.sub_id &&
        form == rhs.form &&
        param_match;
}

