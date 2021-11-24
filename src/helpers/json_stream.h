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
// json_stream.h author Russ Combs <rucombs@cisco.com>

#ifndef JSON_STREAM_H
#define JSON_STREAM_H

// Simple output stream for outputting JSON data.

#include <iostream>
#include "main/snort_types.h"

namespace snort
{
class SO_PUBLIC JsonStream
{
public:
    JsonStream(std::ostream& o) : out(o) { }
    ~JsonStream() = default;

    void open(const char* key = nullptr);
    void close();

    void open_array(const char* key = nullptr);
    void close_array();

    void put(const char* key);    // null
    void put(const char* key, int64_t val);
    void put(const char* key, const char* val);
    void put(const char* key, const std::string& val);
    void put(const char* key, double val, int precision);

    void put_true(const char* key);
    void put_false(const char* key);

private:
    void split();

private:
    std::ostream& out;
    bool sep = false;
    unsigned level = 0;
    unsigned level_array = 0;
};
}
#endif

