---------------------------------------------------------------------------
-- Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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
-- snort_config.lua author Russ Combs <rucombs@cisco.com>

---------------------------------------------------------------------------
-- Snort uses this to configure Lua settings into C++
---------------------------------------------------------------------------

ffi = require("ffi")

ffi.cdef[[
bool open_table(const char*, int);
void close_table(const char*, int);
bool set_bool(const char*, bool);
bool set_number(const char*, double);
bool set_string(const char*, const char*);
bool set_alias(const char*, const char*);
const char* push_relative_path(const char*);
void pop_relative_path();
]]

function include(file)
    local base_name = ffi.C.push_relative_path(file)
    dofile(ffi.string(base_name))
    ffi.C.pop_relative_path()
end

function snort_traverse(tab, fqn)
    local key, val

    for key,val in pairs(tab) do
        -- skip Lua reserved symbols
        if ( string.sub(key, 1, 1) ~= '_' ) then
            if ( type(val) == 'string' ) then
                snort_set(fqn, key, val)
            end
        end
    end

    for key,val in pairs(tab) do
        -- skip Lua reserved symbols
        if ( string.sub(key, 1, 1) ~= '_' ) then
            if ( type(val) ~= 'string' ) then
                snort_set(fqn, key, val)
            end
        end
    end
end

function snort_set(fqn, key, val)
    local name
    local idx = 0
    local what = type(val)
        
    if ( not fqn ) then
        name = key

    elseif ( type(key) == 'number' ) then
        name = fqn
        idx = key

    else
        name = fqn .. '.' .. key
    end

    if ( what == 'boolean' ) then
        ffi.C.set_bool(name, val)

    elseif ( what == 'number' ) then
        ffi.C.set_number(name, val)

    elseif ( what == 'string' ) then
        ffi.C.set_string(name, val)

    elseif ( what == 'table' ) then
        if ( ffi.C.open_table(name, idx) ) then
            snort_traverse(val, name)
            ffi.C.close_table(name, idx)
        end
    end
end

function load_aliases()
    for i,v in ipairs(binder) do
        if ( v.use and type(v.use) == "table" ) then
            if ( v.use.name and v.use.type ) then
                ffi.C.set_alias(v.use.name, v.use.type)
                tab = _G[v.use.name]

                if ( tab ) then
                    snort_set(nil, v.use.name, _G[v.use.name])
                end
            end
        end
    end
end

function snort_config(tab)
    snort_traverse(tab)

    if ( binder and type(binder) == 'table' ) then
        load_aliases()
    end
end

