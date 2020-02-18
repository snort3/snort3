---------------------------------------------------------------------------
-- Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
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
-- bootstrap.lua author Russ Combs <rucombs@cisco.com>

---------------------------------------------------------------------------
-- Snort uses this to configure Lua settings into C++
---------------------------------------------------------------------------

ffi = require("ffi")

ffi.cdef[[
const char* push_include_path(const char*);
void pop_include_path();
void snort_whitelist_append(const char*);
void snort_whitelist_add_prefix(const char*);
]]

function whitelist_append(list, is_prefix)
    for w in list:gmatch("%S+") do
        if ( type(w) == 'string' ) then
            if ( w:match('^%a') ~= nil ) then
                if ( is_prefix ) then
                    ffi.C.snort_whitelist_add_prefix(w)
                else
                    ffi.C.snort_whitelist_append(w)
                end
            end
        end
    end
end

function snort_whitelist_append(list)
    whitelist_append(list, false)
end

function snort_whitelist_add_prefix(list)
    whitelist_append(list, true)
end

function initialize_whitelist(tab)
    for key, val in pairs(tab) do
        -- skip Lua reserved symbols
        if ( string.sub(key, 1, 1) ~= '_' ) then
            if ( type(val) == 'table' ) then
                ffi.C.snort_whitelist_append(key)
            end
        end
    end
end

---------------------------------------------------------------------------
-- path magic for includes
---------------------------------------------------------------------------

function path_push(file)
    if ( _snort_path == nil ) then
        _snort_path = { }
    end
    _snort_path[#_snort_path + 1] = file
end

function path_pop()
    if ( _snort_path == nil ) then
        return
    end
    table.remove(_snort_path, #_snort_path)
end

function path_top()
    if ( _snort_path == nil ) then
        return nil
    end
    return _snort_path[#_snort_path]
end

function include(file)
    local cname = ffi.C.push_include_path(file)
    local fname = ffi.string(cname);
    path_push(fname)
    dofile(fname)
    local iname = path_top()
    if ( (ips ~= nil) and (ips.includer == nil) and (iname ~= nil) ) then
        ips.includer = iname
    end
    path_pop()
    ffi.C.pop_include_path()
end

initialize_whitelist(_G)
initialize_whitelist = nil
