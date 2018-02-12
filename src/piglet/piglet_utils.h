//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// piglet_utils.h author Joel Cornett <jocornet@cisco.com>

#ifndef PIGLET_UTILS_H
#define PIGLET_UTILS_H

// Miscellaneous data objects used for the piglet test harness

#include <chrono>
#include <string>
#include <vector>

namespace Piglet
{
using time_point = std::chrono::time_point<std::chrono::system_clock>;
using duration = std::chrono::duration<double>;

// -------------------------------------------------------------------------
// Timer
// -------------------------------------------------------------------------
struct Timer
{
    using system_clock = std::chrono::system_clock;
    using time_point = std::chrono::time_point<system_clock>;
    using duration = std::chrono::duration<double>;

    time_point start_time, stop_time;

    bool running = false;

    void start();
    void stop();

    inline duration delta()
    { return stop_time - start_time; }

    // chrono::microseconds d = chrono::duration_cast<microseconds>(dur);
    // d.count();
};

// -------------------------------------------------------------------------
// Chunk
// -------------------------------------------------------------------------
struct Chunk
{
    std::string filename;
    std::string target;
    std::string buffer;

    Chunk(const std::string& f, const std::string& t, const std::string& b) :
        filename { f }, target { t }, buffer { b } { }
};

// -------------------------------------------------------------------------
// Test
// -------------------------------------------------------------------------
struct Test
{
    enum Result
    {
        NA = -1,
        PASSED = 0,
        FAILED,
        ERROR
    };

    const Chunk* chunk;
    Timer timer;

    Result result = NA;

    std::string type;
    std::string name;
    std::string description;
    bool use_defaults = false;

    std::vector<std::string> messages;

    inline void set_error(const std::string& s)
    {
        result = ERROR;
        messages.push_back(s);
    }

    Test(const Chunk& ch) : chunk { &ch } { }
};
} // namespace Piglet

#endif

