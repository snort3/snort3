//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

#include <string>

#include "framework/base_api.h"
#include "helpers/lua.h"

namespace Piglet
{
using namespace std;

//--------------------------------------------------------------------------
// Base Plugin
//--------------------------------------------------------------------------

struct Api;

class SO_PUBLIC BasePlugin
{
public:
    BasePlugin(Lua::Handle& handle, string t) :
        lua { handle }, target { t } { }

    virtual ~BasePlugin() { }

    // Setup the Lua environment for the test
    virtual bool setup()
    { return false; }

    void set_api(const Api* p)
    { api = p; }

    const Api* get_api()
    { return api; }

    string get_error()
    { return error; }

protected:
    Lua::Handle lua;

    string target;
    string error;

    void set_error(string s)
    { error = s; }

private:
    const Api* api;
};

//--------------------------------------------------------------------------
// Plugin ctor/dtor
//--------------------------------------------------------------------------

using PluginCtor = BasePlugin* (*)(Lua::Handle&, string, Module*);
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

//--------------------------------------------------------------------------
// API constant declarations
//--------------------------------------------------------------------------

extern const unsigned int API_VERSION;
extern const unsigned int API_SIZE;
extern const char* API_HELP;
} // namespace Piglet

#endif

