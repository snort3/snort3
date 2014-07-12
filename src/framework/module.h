/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
// module.h author Russ Combs <rucombs@cisco.com>

// FIXIT 
// -- add get method
// -- add set_default method
// -- add stats/pegs and profiling
// -- move to respective source files / dirs once complete
// -- add trace param(s)
// -- add memcap related
// -- add optional startup param output

#ifndef MODULE_H
#define MODULE_H

#include <lua.hpp>

#include "framework/value.h"
#include "framework/parameter.h"

struct SnortConfig;

struct Command
{
    const char* name;
    lua_CFunction func;
    const char* help;
};

struct RuleMap
{
    unsigned sid;
    const char* msg;
};

struct ProfileStats;

class Module
{
public:
    virtual ~Module() { };

    // for lists (tables with numeric indices):
    // int == 0 is list container
    // int > 0 is list item
    virtual bool begin(const char*, int, SnortConfig*)
    { return true; };

    virtual bool end(const char*, int, SnortConfig*)
    { return true; };

    virtual bool set(const char*, Value&, SnortConfig*) = 0;

    virtual unsigned get_gid() const
    { return 0; };

    // profile is thread local
    virtual ProfileStats* get_profile() const
    { return nullptr; };

    // implement above -or- below
    virtual ProfileStats* get_profile(
        unsigned /*index*/, const char*& /*name*/, const char*& /*parent*/) const
    { return nullptr; };

    const char* get_name() const
    { return name ? name : params->name; };

    bool is_table() const
    { return (name != nullptr); };

    bool is_list() const
    { return list; };

    Parameter::Type get_type() const
    {
        if ( is_list() )
            return Parameter::PT_LIST;
        else if ( is_table() )
            return Parameter::PT_TABLE;
        else
            return params->type;
    };

    const Parameter* get_parameters() const
    { return params; };

    const Command* get_commands() const
    { return cmds; };

    const RuleMap* get_rules() const
    { return rules; };

protected:
    Module(const char* s, const Parameter* p, bool is_list = false)
    { init(s, p); list = is_list; };

    Module(const char* s, const Parameter* p, const RuleMap* r)
    { init(s, p); rules = r; };

    Module(const char* s, const Parameter* p, const Command* c)
    { init(s, p); cmds = c; };

    Module(const char* s, const Parameter* p, const RuleMap* r, const Command* c)
    { init(s, p); rules = r; cmds = c; };

private:
    friend class ModuleManager;

    void init(const char* s, const Parameter* p)
    { name = s; params = p; list = false; cmds = nullptr; rules = nullptr; };

    bool list;
    const char* name;
    const Parameter* params;
    const Command* cmds;
    const RuleMap* rules;
};

#endif

