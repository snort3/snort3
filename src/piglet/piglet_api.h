//--------------------------------------------------------------------------
// Copyright (C) 2015-2017 Cisco and/or its affiliates. All rights reserved.
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
// piglet_api.h author Joel Cornett <jocornet@cisco.com>

#ifndef PIGLET_API_H
#define PIGLET_API_H

// Piglet plugin API

#include <string>

#include "framework/base_api.h"
#include "log/messages.h"
#include "lua/lua.h"
#include "main/snort_types.h"

struct lua_State;
class Module;
struct SnortConfig;

#define PIGLET_API_VERSION 1

namespace Piglet
{
//--------------------------------------------------------------------------
// Base Plugin
//--------------------------------------------------------------------------

struct Api;

class SO_PUBLIC BasePlugin
{
public:
    BasePlugin(Lua::State& lua, const std::string& t,
        Module* m = nullptr, SnortConfig* sc = nullptr) :
        L { lua.get_ptr() }, target { t },
        module { m }, snort_conf { sc } { }

    virtual ~BasePlugin() { }

    // Setup the Lua environment for the test
    virtual bool setup()
    { return false; }

    void set_api(const Api* p)
    { api = p; }

    const Api* get_api()
    { return api; }

    std::string get_error()
    { return error; }

protected:
    lua_State* L;
    std::string target;
    Module* module;
    SnortConfig* snort_conf;

    std::string error;  // FIXIT-L unused

    void set_error(const std::string& s)  // FIXIT-L unused
    { error = s; }

private:
    const Api* api;
};

//--------------------------------------------------------------------------
// Plugin ctor/dtor
//--------------------------------------------------------------------------

using PluginCtor = BasePlugin* (*)(Lua::State&, std::string, Module*, SnortConfig*);
using PluginDtor = void (*)(BasePlugin*);

//--------------------------------------------------------------------------
// Plugin Api
//--------------------------------------------------------------------------

struct Api
{
    BaseApi base;
    PluginCtor ctor;
    PluginDtor dtor;
    PlugType target;
};

template<typename... Args>
inline void error(std::string fmt, Args&&... args)
{
    fmt.insert(0, "piglet: ");
    fmt.append("\n");
    ErrorMessage(fmt.c_str(), std::forward<Args>(args)...);
}

} // namespace Piglet

#endif

