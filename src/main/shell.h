//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// shell.h author Russ Combs <rucombs@cisco.com>

#ifndef SHELL_H
#define SHELL_H

// Shell encapsulates a Lua state.  There is one for each policy file.

#include <string>

struct lua_State;

namespace snort
{
struct SnortConfig;
}

class Shell
{
public:
    Shell(const char* file = nullptr);
    ~Shell();

    void set_file(const char*);
    void set_overrides(const char*);
    void set_overrides(Shell*);

    void configure(snort::SnortConfig*);
    void install(const char*, const struct luaL_Reg*);
    void execute(const char*, std::string&);

    const char* get_file() const
    { return file.c_str(); }

    bool get_loaded() const
    { return loaded; }

private:
    [[noreturn]] static int panic(lua_State*);
    static std::string fatal;

private:
    bool loaded;
    lua_State* lua;
    std::string file;
    std::string parse_from;
    std::string overrides;
};

#endif

