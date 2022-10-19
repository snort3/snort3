//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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
// cursor.h author Russ Combs <rucombs@cisco.com>

#ifndef CURSOR_H
#define CURSOR_H

// Cursor provides a formal way of using buffers when doing detection with
// IpsOptions.

#include <assert.h>
#include <cstdint>
#include <cstring>
#include <vector>

#include "main/snort_types.h"

namespace snort
{
struct Packet;
}

class CursorData
{
public:
    CursorData(unsigned u) : id(u) {}
    virtual ~CursorData() = default;
    virtual CursorData* clone() = 0;

    unsigned get_id()
    { return id; }

    static unsigned create_cursor_data_id()
    { return ++cursor_data_id; }

private:
    static unsigned cursor_data_id;
    unsigned id;
};

class SO_PUBLIC Cursor
{
public:
    Cursor() = default;
    Cursor(snort::Packet*);
    Cursor(const Cursor&);

    Cursor& operator=(const Cursor&) = delete;

    ~Cursor()
    {
        if (!data)
            return;

        for (CursorData*& cd : *data)
            delete cd;

        delete data;
    }

    const char* get_name() const
    { return name; }

    bool is(const char* s) const
    { return !strcmp(name, s); }

    void reset(snort::Packet*);

    void set(const char* s, const uint8_t* b, unsigned n, bool ext = false)
    {
        name = s; buf = b; buf_size = n; current_pos = delta = 0;
        extensible = ext and n > 0;
        buf_id = 0;
    }

    void set(const char* s, const uint8_t* b, unsigned n, unsigned pos_file, bool ext = false)
    {
        file_pos = pos_file;
        name = s; buf = b; buf_size = n; current_pos = delta = 0;
        extensible = ext and n > 0;
        buf_id = 0;
    }

    void set(const char* s, uint64_t id, const uint8_t* b, unsigned n, bool ext = false)
    {
        set(s, b, n, ext);
        buf_id = id;
    }

    void set(const char* s, uint64_t id, const uint8_t* b, unsigned n, unsigned pos_file, bool ext = false)
    {
        set(s, b, n, pos_file, ext);
        buf_id = id;
    }

    uint64_t id() const
    { return buf_id; }

    const uint8_t* buffer() const
    { return buf; }

    unsigned size() const
    { return buf_size; }

    // the NEXT octect after last in buffer
    // (this pointer is out of bounds)
    const uint8_t* endo() const
    { return buf + buf_size; }

    const uint8_t* start() const
    { return buf + current_pos; }

    unsigned length() const
    { return buf_size - current_pos; }

    unsigned get_pos() const
    { return current_pos; }

    unsigned get_delta() const
    { return delta; }

    CursorData* get_data(unsigned id) const;

    bool add_pos(unsigned n)
    {
        current_pos += n;
        return !(current_pos > buf_size);
    }

    // current_pos and delta may go 1 byte after end
    bool set_pos(unsigned n)
    {
        current_pos = n;
        return !(current_pos > buf_size);
    }

    bool set_pos_file(unsigned n)
    {
        file_pos = n;
        return true;
    }

    bool set_accumulation(bool is_accum)
    {
        is_accumulated = is_accum;
        return true;
    }

    unsigned get_file_pos() const
    {
        return file_pos;
    }

    bool is_buffer_accumulated() const
    {
        return is_accumulated;
    }

    bool set_delta(unsigned n)
    {
        if (n > buf_size)
            return false;
        delta = n;
        return true;
    }

    void set_data(CursorData* cd);

    bool awaiting_data() const
    { return extensible and current_pos >= buf_size; }

    bool awaiting_data(bool force_ext) const
    { return force_ext and current_pos >= buf_size; }

    unsigned get_next_pos() const
    {
        assert(current_pos >= buf_size);
        return current_pos - buf_size;
    }

    typedef std::vector<CursorData*> CursorDataVec;

private:
    unsigned buf_size = 0;
    unsigned current_pos = 0;
    unsigned delta = 0;            // loop offset
    unsigned file_pos = 0;         // file pos
    const uint8_t* buf = nullptr;
    const char* name = nullptr;    // rule option name ("pkt_data", "http_uri", etc.)
    CursorDataVec* data = nullptr; // data stored on the cursor
    bool extensible = false;       // if the buffer could have more data in a continuation
    uint64_t buf_id = 0;           // source buffer ID
    bool is_accumulated = false;
};

#endif

