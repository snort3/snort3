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
// module.h author Russ Combs <rucombs@cisco.com>

// FIXIT-M add trace param(s)
// FIXIT-M add memcap related
// FIXIT-L add set_default method

#ifndef MODULE_H
#define MODULE_H

// Module provides a data-driven way to manage much of Snort++.  For
// example, it provides an interface to configured components.  There is at
// most one instance of a Module at any time.  A given module instance is
// used to configure all related components.  As such it stores data only
// for the sake of constructing the next component instance.
//
// Module will set all parameter defaults immediately after calling
// begin() so defaults should not be explicitly set in begin() or a ctor
// called by begin, except as needed for infrastructure and sanity.
//
// Note that there are no internal default lists.  Put appropriate default
// lists in snort_defaults.lua or some such.  Each list item, however, will
// have any defaults applied.

#include <cassert>
#include <string>
#include <vector>

#include "framework/counts.h"
#include "framework/parameter.h"
#include "framework/value.h"
#include "main/snort_debug.h"
#include "main/snort_types.h"
#include "utils/stats.h"

struct lua_State;

class ModuleManager;

namespace snort
{
struct ProfileStats;
struct SnortConfig;

using LuaCFunction = int(*)(lua_State*);

struct Command
{
    const char* name;
    LuaCFunction func;
    const Parameter* params;
    const char* help;

    std::string get_arg_list() const;
};

struct RuleMap
{
    unsigned sid;
    const char* msg;
};

class SO_PUBLIC Module
{
public:
    virtual ~Module() = default;

    // configuration:
    // for lists (tables with numeric indices):
    // int == 0 is list container
    // int > 0 is list item
    virtual bool begin(const char*, int, SnortConfig*)
    { return true; }

    virtual bool end(const char*, int, SnortConfig*)
    { return true; }

    virtual bool set(const char*, Value&, SnortConfig*);

    // ips events:
    virtual unsigned get_gid() const
    { return 0; }

    const char* get_name() const
    { return name ? name : params->name; }

    bool is_table() const
    { return (name != nullptr); }

    bool is_list() const
    { return list; }

    Parameter::Type get_type() const
    {
        if ( is_list() )
            return Parameter::PT_LIST;
        else if ( is_table() )
            return Parameter::PT_TABLE;
        else
            return params->type;
    }

    const char* get_help() const
    { return help; }

    const Parameter* get_parameters() const
    { return params; }

    const Parameter* get_default_parameters() const
    { return default_params; }

    virtual const Command* get_commands() const
    { return nullptr; }

    virtual const RuleMap* get_rules() const
    { return nullptr; }

    virtual const PegInfo* get_pegs() const
    { return nullptr; }

    // counts and profile are thread local
    virtual PegCount* get_counts() const
    { return nullptr; }

    virtual int get_num_counts() const
    { return num_counts; }

    virtual ProfileStats* get_profile() const
    { return nullptr; }

    // implement above -or- below
    virtual ProfileStats* get_profile(
        unsigned /*index*/, const char*& /*name*/, const char*& /*parent*/) const
    { return nullptr; }

    virtual const char* get_defaults() const
    { return nullptr; }

    virtual bool global_stats() const
    { return false; }

    virtual void sum_stats(bool accumulate_now_stats);
    virtual void show_interval_stats(IndexVec&, FILE*);
    virtual void show_stats();
    virtual void reset_stats();

    // Wrappers to check that lists are not tables
    bool verified_begin(const char*, int, SnortConfig*);
    bool verified_set(const char*, Value&, SnortConfig*);
    bool verified_end(const char*, int, SnortConfig*);

    enum Usage
    {
        GLOBAL,
        CONTEXT,
        INSPECT,
        DETECT
    };

    virtual Usage get_usage() const
    { return CONTEXT; }

protected:
    Module(const char* name, const char* help);
    Module(const char* name, const char* help, const Parameter*,
        bool is_list = false, Trace* = nullptr);

private:
    friend ModuleManager;
    void init(const char*, const char* = nullptr);

    std::vector<PegCount> counts;
    int num_counts = -1;

    const char* name;
    const char* help;

    const Parameter* params;
    const Parameter* default_params = nullptr;
    bool list;
    int table_level = 0;

    Trace* trace;

    void set_peg_count(int index, PegCount value)
    {
        assert(index < num_counts);
        counts[index] = value;
    }

    void set_max_peg_count(int index, PegCount value)
    {
        assert(index < num_counts);
        if(value > counts[index])
            counts[index] = value;
    }

    void add_peg_count(int index, PegCount value)
    {
        assert(index < num_counts);
        counts[index] += value;
    }
};
}
#endif

