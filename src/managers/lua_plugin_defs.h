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
// lua_plugin_defs.h

#ifndef LUA_PLUGIN_DEFS_H
#define LUA_PLUGIN_DEFS_H

#include <cstdint>

struct SnortBuffer
{
    const char* type;
    const uint8_t* data;
    unsigned len;
};

extern "C"
const struct SnortBuffer* get_buffer();

struct SnortEvent
{
    unsigned gid;
    unsigned sid;
    unsigned rev;

    uint32_t event_id;
    uint32_t event_ref;

    const char* msg;
    const char* svc;
};

extern "C"
const struct SnortEvent* get_event();

struct SnortPacket
{
    // FIXIT-L add ip addrs and other useful foo to lua packet
    const char* type;
    uint64_t num;
    unsigned sp;
    unsigned dp;
};

extern "C"
const struct SnortPacket* get_packet();

#endif
