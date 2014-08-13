/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef IPS_LUAJIT_H
#define IPS_LUAJIT_H

#include <string>
#include "framework/ips_option.h"
#include "framework/module.h"

class LuaJitModule : public Module
{
public:
    LuaJitModule(const char* name);

    bool begin(const char*, int, SnortConfig*);
    bool set(const char*, Value&, SnortConfig*);

    ProfileStats* get_profile() const;

public:
    std::string args;
};

class LuaJitOption : public IpsOption
{
public:
    LuaJitOption(const char* name, std::string& chunk, LuaJitModule*);
    ~LuaJitOption();

    uint32_t hash() const;
    bool operator==(const IpsOption&) const;

    int eval(Cursor&, Packet*);

private:
    void init(const char*, const char*);

    std::string config;
    struct lua_State** lua;
};

#endif

