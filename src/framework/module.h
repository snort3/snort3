//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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
#include "main/snort_types.h"
#include "utils/stats.h"

struct lua_State;

namespace snort
{
class ModuleManager;
class Trace;
struct ProfileStats;
struct SnortConfig;
struct TraceOption;

using LuaCFunction = int(*)(lua_State*);

struct Command
{
    const char* name;
    LuaCFunction func;
    const Parameter* params;
    const char* help;
    // the flag determines if the command is allowed to run in parallel with other control commands
    bool can_run_in_parallel = false;

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

    virtual bool set(const char*, Value&, SnortConfig*)
    { return true; }

    virtual void set_trace(const Trace*) const { }

    virtual const TraceOption* get_trace_options() const
    { return nullptr; }

    // used to match parameters with $var names like <gid:sid> for rule_state
    virtual bool matches(const char* /*param_name*/, std::string& /*lua_name*/)
    { return false; }

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

    virtual const Command* get_commands() const
    { return nullptr; }

    virtual const RuleMap* get_rules() const
    { return nullptr; }

    virtual const PegInfo* get_pegs() const
    { return nullptr; }

    virtual bool counts_need_prep() const
    { return false; }

    virtual void prep_counts(bool) { }

    // counts and profile are thread local
    virtual PegCount* get_counts() const
    { return nullptr; }

    virtual PegCount get_global_count(const char* name) const;

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

    virtual void sum_stats(bool dump_stats);
    virtual void show_interval_stats(IndexVec&, FILE*);
    virtual void show_stats();
    virtual void reset_stats();
    virtual void show_dynamic_stats() {}
    void clear_global_active_counters();

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

    virtual bool is_bindable() const
    { return false; }

protected:
    Module(const char* name, const char* help);
    Module(const char* name, const char* help, const Parameter*, bool is_list = false);

    void set_params(const Parameter* p)
    { params = p; }

    bool dump_stats_initialized = false;

    std::vector<PegCount> counts;
    std::vector<PegCount> dump_stats_counts;
    int num_counts = -1;

    void set_peg_count(int index, PegCount value, bool dump_stats = false)
    {
        assert(index < num_counts);
        if(dump_stats)
            dump_stats_counts[index] = value;
        else
            counts[index] = value;
    }

    void add_peg_count(int index, PegCount value, bool dump_stats = false)
    {
        assert(index < num_counts);
        if(dump_stats)
            dump_stats_counts[index] += value;
        else
            counts[index] += value;
    }

private:
    friend ModuleManager;
    void init(const char*, const char* = nullptr);

    const char* name;
    const char* help;

    const Parameter* params;
    bool list;
    int table_level = 0;

    void set_max_peg_count(int index, PegCount value, bool dump_stats = false)
    {
        assert(index < num_counts);
        if(dump_stats)
        {
            if(value > dump_stats_counts[index])
                dump_stats_counts[index] = value;
        }
        else
        {
            if(value > counts[index])
                counts[index] = value;
        }
    }
};
}
#endif

