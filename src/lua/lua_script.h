//--------------------------------------------------------------------------
// Copyright (C) 2015-2021 Cisco and/or its affiliates. All rights reserved.
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
// lua_script.h author Joel Cornett <jocornet@cisco.com>

#ifndef LUA_SCRIPT_H
#define LUA_SCRIPT_H

#include <string>

#include <lua.hpp>

#define LUA_DIR_SEP '/'
#define SCRIPT_DIR_VARNAME "SCRIPT_DIR"

namespace Lua
{
inline void set_script_dir(
    lua_State* L, const std::string& varname, const std::string& path)
{
    std::string dir = path.substr(0, path.rfind(LUA_DIR_SEP));
    lua_pushlstring(L, dir.c_str(), dir.size());
    lua_setglobal(L, varname.c_str());
}
}
#endif
