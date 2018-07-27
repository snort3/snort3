//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// http_field.h author Tom Peters <thopeter@cisco.com>

#ifndef HTTP_FIELD_H
#define HTTP_FIELD_H

#include <cstdint>
#include <cstdio>
#include <cassert>

#include "http_enum.h"

// Individual pieces of the message found during parsing.
// Length values <= 0 are StatusCode values and imply that the start pointer is meaningless.
// Never use the start pointer without verifying that length > 0.
class Field
{
public:
    static const Field FIELD_NULL;

    Field(int32_t length, const uint8_t* start, bool own_the_buffer_ = false) : strt(start),
        len(length), own_the_buffer(own_the_buffer_) { assert(length <= HttpEnums::MAX_OCTETS); }
    explicit Field(int32_t length) : len(length) { assert(length<=0); }
    Field() = default;
    ~Field() { if (own_the_buffer) delete[] strt; }
    int32_t length() const { return len; }
    const uint8_t* start() const { return strt; }
    void set(int32_t length, const uint8_t* start, bool own_the_buffer_ = false);
    void set(const Field& f);
    void set(HttpEnums::StatusCode stat_code);
    void set(int32_t length) { set(static_cast<HttpEnums::StatusCode>(length)); }

#ifdef REG_TEST
    void print(FILE* output, const char* name) const;
#endif

private:
    Field& operator=(const Field&) = delete;

    const uint8_t* strt = nullptr;
    int32_t len = HttpEnums::STAT_NOT_COMPUTE;
    bool own_the_buffer = false;
};

#endif

