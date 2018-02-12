//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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
// curses.h author Maya Dagon <mdagon@cisco.com>

#ifndef CURSES_H
#define CURSES_H

#include <cstdint>
#include <string>
#include <vector>

enum DCE_States
{
    STATE_0 = 0,
    STATE_1,
    STATE_2,
    STATE_3,
    STATE_4,
    STATE_5,
    STATE_6,
    STATE_7,
    STATE_8,
    STATE_9,
    STATE_10
};

class CurseTracker
{
public:
    DCE_States state;
    uint32_t helper;

    CurseTracker() { state = STATE_0; }
};

typedef bool (* curse_alg)(const uint8_t* data, unsigned len, CurseTracker*);

struct CurseDetails
{
    std::string name;
    std::string service;
    curse_alg alg;
    bool is_tcp;
};

class CurseBook
{
public:
    bool add_curse(const char* service);
    const std::vector<const CurseDetails*>& get_curses(bool tcp) const;

private:
    std::vector<const CurseDetails*> tcp_curses;
    std::vector<const CurseDetails*> non_tcp_curses;
};

#endif

