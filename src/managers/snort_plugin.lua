---------------------------------------------------------------------------
-- Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
--
-- This program is free software; you can redistribute it and/or modify it
-- under the terms of the GNU General Public License Version 2 as published
-- by the Free Software Foundation.  You may not use, modify or distribute
-- this program under any other version of the GNU General Public License.
--
-- This program is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
-- General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
---------------------------------------------------------------------------
-- snort_plugin.lua author Russ Combs <rucombs@cisco.com>

ffi = require("ffi")

ffi.cdef[[
struct SnortBuffer
{
    const char* type;
    const uint8_t* data;
    unsigned len;
};
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
    const char* os;
};
const struct SnortEvent* get_event();

struct SnortPacket
{
    const char* type;
    uint64_t num;
    unsigned sp;
    unsigned dp;
};
const struct SnortPacket* get_packet();
]]

