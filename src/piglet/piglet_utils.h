//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

#include <chrono>
#include <string>
#include <vector>

namespace Piglet
{
using namespace std;

// -------------------------------------------------------------------------
// Timer
// -------------------------------------------------------------------------

struct Timer
{
    chrono::time_point<chrono::system_clock> start_time, stop_time;

    bool running = false;

    void start();
    void stop();

    chrono::duration<double> delta();

    // chrono::microseconds d = chrono::duration_cast<microseconds>(dur);
    // d.count();
};

// -------------------------------------------------------------------------
// Chunk
// -------------------------------------------------------------------------

struct Chunk
{
    Chunk(string f, string s) :
        filename(f), buffer(s) { }

    string filename, buffer;
};

// -------------------------------------------------------------------------
// Test
// -------------------------------------------------------------------------

struct Test
{
    string name, type, target;
    vector<string> messages;
    string _message;

    const Chunk* chunk;

    bool result = false;
    bool error = false;

    Timer timer;

    Test& operator<<(string);
    void endl();
};
} // namespace Piglet

#endif

