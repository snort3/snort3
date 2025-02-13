---------------------------------------------------------------------------
-- Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
-- builtin_defaults.lua author Russ Combs <rucombs@cisco.com>

---------------------------------------------------------------------------
-- Snort uses this to configure Lua settings into C++
---------------------------------------------------------------------------

-- builtin modules are included to always set defaults via parameters instead
-- of putting defaults in two places
-- these are loaded first and will get overridden if configured by the user
-- these modules are virtually always in play

active = { }
alerts = { }
daq = { }
decode = { }
host_cache = { }
host_tracker = { }
hosts = { }
network = { }
output = { }
packets = { }
process = { }
search_engine = { }
so_proxy = { }
trace = { }

-- exceptions:

--[[
attribute_table = { }    -- opt in only
classifications = { }    -- pure list
detection = { }          -- policy specific
event_filter = { }       -- pure list
event_queue = { }        -- pure list
file_id = { }            -- opt in
high_availability = { }  -- opt in
inspection = { }         -- policy specific
ips = { }                -- policy specific
latency = { }            -- don't activate
memory = { }             -- opt in
packet_tracer = { }      -- opt in
perf_monitor = { }       -- opt in
port_scan = { }          -- opt in
profiler = { }           -- don't activate
rate_filter = { }        -- pure list
references = { }         -- pure list
side_channel = { }       -- leaks!
snort = { }              -- command line only
suppress = { }           -- pure list
--]]

