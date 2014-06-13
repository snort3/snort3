---------------------------------------------------------------------------
-- Copyright (C) 2014-2014 Sourcefire, Inc.
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License Version 2 as
-- published by the Free Software Foundation.  You may not use, modify or
-- distribute this program under any other version of the GNU General
-- Public License.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
---------------------------------------------------------------------------

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
]]

function include(file)
    print('Loading ' .. file)
    dofile(file)
end

function snort_traverse(tab, fqn)
    local key, val

    for key,val in pairs(tab) do
        -- skip Lua reserved symbols
        if ( string.sub(key, 1, 1) ~= '_' ) then
            snort_set(fqn, key, val)
        end
    end
end

function snort_set(fqn, key, val)
    local name
    local idx = 0
        
    if ( not fqn ) then
        name = key
    elseif ( type(key) == 'number' ) then
        name = fqn
        idx = key
    else
        name = fqn .. '.' .. key
    end

    local what = type(val)

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

function snort_config()
    snort_traverse(_G)
end

