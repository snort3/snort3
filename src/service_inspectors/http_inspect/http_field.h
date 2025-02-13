//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_types.h"

#include "http_common.h"

// Individual pieces of the message found during parsing.
// Length values <= 0 are StatusCode values and imply that the start pointer is meaningless.
// Never use the start pointer without verifying that length > 0.
class SO_PUBLIC Field
{
public:
    static const Field FIELD_NULL;

    Field(int32_t length, const uint8_t* start, bool own_the_buffer_ = false);
    explicit Field(int32_t length) : len(length) { assert(length<=0); }
    Field() = default;

    // own_the_buffer precludes trivial copy assignment
    Field& operator=(const Field& rhs) = delete;

    ~Field() { if (own_the_buffer) delete[] strt; }
    int32_t length() const { return len; }
    const uint8_t* start() const { return strt; }
    void set(int32_t length, const uint8_t* start, bool own_the_buffer_ = false);
    void set(const Field& f);
    void set(HttpCommon::StatusCode stat_code);
    void set(int32_t length) { set(static_cast<HttpCommon::StatusCode>(length)); }
    void reset();
    void set_accumulation(bool is_accum) { was_accumulated = is_accum; }
    bool is_accumulated() const { return was_accumulated; }

#ifdef REG_TEST
    void print(FILE* output, const char* name) const;
#endif

private:
    const uint8_t* strt = nullptr;
    int32_t len = HttpCommon::STAT_NOT_COMPUTE;
    bool own_the_buffer = false;
    // FIXIT-M: find better place for the attribute, replace it with actual number of bytes processed
    bool was_accumulated = false;
};

struct MimeBufs
{
    Field file;
    Field vba;
    MimeBufs(int32_t file_len, const uint8_t* file_buf, bool file_own, int32_t vba_len, const uint8_t* vba_buf,
        bool vba_own) :
        file(file_len, file_buf, file_own),
        vba(vba_len, vba_buf, vba_own) {}
};

#endif

