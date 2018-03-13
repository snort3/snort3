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
// lua_api.h author Joel Cornett <jocornet@cisco.com>

#ifndef LUA_API_H
#define LUA_API_H

// LuaApi makes Lua scripts standard plugins

#include <string>

namespace snort
{
struct BaseApi;
}

class LuaApi
{
public:
    virtual ~LuaApi() = default;
    virtual const snort::BaseApi* get_base() const = 0;

    std::string name;
    std::string chunk;

protected:
    LuaApi(std::string& s, std::string& c)
    {
        name = s;
        chunk = c;
    }
};

#endif

