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
// http_buffer_info.h author Brandon Stultz <brastult@cisco.com>

#ifndef HTTP_BUFFER_INFO_H
#define HTTP_BUFFER_INFO_H

#include "main/snort_types.h"

class HttpBufferInfo
{
public:
    HttpBufferInfo(unsigned type_, uint64_t sub_id_ = 0, uint64_t form_ = 0)
        : type(type_), sub_id(sub_id_), form(form_) {}

    uint32_t hash() const;

    bool operator==(const HttpBufferInfo& rhs) const;
    bool is_request() const;

public:
    const unsigned type;
    const uint64_t sub_id;
    const uint64_t form;
};

#endif

