//--------------------------------------------------------------------------
// Copyright (C) 2015-2023 Cisco and/or its affiliates. All rights reserved.
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

// profiler_module.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "profiler_module.h"

#include "control/control.h"
#include "hash/xhash.h"
#include "log/messages.h"
#include "main/analyzer_command.h"
#include "main/reload_tuner.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"

#include "profiler/rule_profiler.h"
#include "profiler/rule_profiler_defs.h"

using namespace snort;

#define profiler_help \
    "configure profiling of rules and/or modules"

struct SigInfo;
struct OtnState;

//-------------------------------------------------------------------------
// commands
//-------------------------------------------------------------------------

class ProfilerControl : public AnalyzerCommand
{
public:
    enum CommandType
    {
        ENABLE,
        DISABLE
    };

    ProfilerControl(CommandType action)
        : action(action)
    {}

    bool execute(Analyzer&, void**) override
    {
        switch (action)
        {
        case ENABLE:
            RuleContext::set_enabled(true);
            break;
        case DISABLE:
            RuleContext::set_enabled(false);
            break;
        default:
            return false;
        }
        return true;
    }

    const char *stringify() override { return "PROFILER_CONTROL"; }

private:
    CommandType action;
};

class ProfilerRuleDump : public AnalyzerCommand
{
public:
    ProfilerRuleDump(ControlConn* conn)
        : AnalyzerCommand(conn), nodes(), stats()
    {
        const SnortConfig* sc = SnortConfig::get_conf();
        assert(sc);

        auto doth = sc->detection_option_tree_hash_table;

        if (!doth)
            return;

        for (HashNode* hnode = doth->find_first_node(); hnode; hnode = doth->find_next_node())
        {
            nodes.emplace_back(hnode);
        }
    }

    ~ProfilerRuleDump() override
    {
        const auto* config = SnortConfig::get_conf()->get_profiler();
        assert(config);

        print_rule_profiler_stats(config->rule, stats, ctrlcon);
    }

    bool execute(Analyzer&, void**) override
    {
        prepare_rule_profiler_stats(nodes, stats, get_instance_id());

        return true;
    }

    const char *stringify() override { return "PROFILER_RULE_DUMP"; }

private:
    std::vector<HashNode*> nodes;
    std::unordered_map<SigInfo*, OtnState> stats;
};

class ProfilerRuleReset : public AnalyzerCommand
{
public:
    ProfilerRuleReset() : nodes()
    {
        const SnortConfig* sc = SnortConfig::get_conf();
        assert(sc);

        auto doth = sc->detection_option_tree_hash_table;

        if (!doth)
            return;

        for (HashNode* hnode = doth->find_first_node(); hnode; hnode = doth->find_next_node())
        {
            nodes.emplace_back(hnode);
        }
    }

    bool execute(Analyzer&, void**) override
    {
        reset_thread_rule_profiler_stats(nodes, get_instance_id());

        return true;
    }

    const char *stringify() override { return "PROFILER_RULE_RESET"; }

private:
    std::vector<HashNode*> nodes;
};

static int rule_profiling_start(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);

    if (RuleContext::is_enabled())
    {
        LogRespond(ctrlcon, "Rule profiler is already running\n");
        return 0;
    }

    RuleContext::set_enabled(true);
    main_broadcast_command(new ProfilerControl(ProfilerControl::CommandType::ENABLE), ctrlcon);
    main_broadcast_command(new ProfilerRuleReset(), ctrlcon);
    LogRespond(ctrlcon, "Rule profiler started\n");
    LogRespond(ctrlcon, "Configuration reload id: %u\n", SnortConfig::get_conf()->get_reload_id());

    return 0;
}

static int rule_profiling_stop(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);

    if (!RuleContext::is_enabled())
    {
        LogRespond(ctrlcon, "Rule profiler is not running\n");
        return 0;
    }

    RuleContext::set_enabled(false);
    main_broadcast_command(new ProfilerControl(ProfilerControl::CommandType::DISABLE), ctrlcon);
    LogRespond(ctrlcon, "Rule profiler stopped\n");

    return 0;
}

static int rule_profiling_status(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);

    LogRespond(ctrlcon, "Rule profiler is %s\n", RuleContext::is_enabled() ?
        "enabled" : "disabled");

    return 0;
}

static int rule_profiling_dump(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);

    if (!RuleContext::is_enabled())
    {
        LogRespond(ctrlcon, "Rule profiler is off\n");
        return 0;
    }

    main_broadcast_command(new ProfilerRuleDump(ctrlcon), ctrlcon);

    return 0;
}

static const Command profiler_cmds[] =
{
    { "rule_start", rule_profiling_start,
      nullptr, "enable rule profiler" },

    { "rule_stop", rule_profiling_stop,
      nullptr, "disable rule profiler" },

    { "rule_status", rule_profiling_status,
      nullptr, "print rule profiler status" },

    { "rule_dump", rule_profiling_dump,
      nullptr, "print rule statistics" },

    { nullptr, nullptr, nullptr, nullptr }
};

const Command* ProfilerModule::get_commands() const
{ return profiler_cmds; }

static const Parameter profiler_time_params[] =
{
    { "show", Parameter::PT_BOOL, nullptr, "true",
      "show module time profile stats" },

    { "count", Parameter::PT_INT, "0:max32", "0",
      "limit results to count items per level (0 = no limit)" },

    { "sort", Parameter::PT_ENUM,
      "none | checks | avg_check | total_time ",
      "total_time", "sort by given field" },

    { "max_depth", Parameter::PT_INT, "-1:255", "-1",
      "limit depth to max_depth (-1 = no limit)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter profiler_memory_params[] =
{
    { "show", Parameter::PT_BOOL, nullptr, "true",
      "show module memory profile stats" },

    { "count", Parameter::PT_INT, "0:max32", "0",
      "limit results to count items per level (0 = no limit)" },

    { "sort", Parameter::PT_ENUM,
      "none | allocations | total_used | avg_allocation ",
      "total_used", "sort by given field" },

    { "max_depth", Parameter::PT_INT, "-1:255", "-1",
      "limit depth to max_depth (-1 = no limit)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter profiler_rule_params[] =
{
    { "show", Parameter::PT_BOOL, nullptr, "true",
      "show rule time profile stats" },

    { "count", Parameter::PT_INT, "0:max32", "0",
      "print results to given level (0 = all)" },

    { "sort", Parameter::PT_ENUM,
      "none | checks | avg_check | total_time | matches | no_matches | "
      "avg_match | avg_no_match",
      "total_time", "sort by given field" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter profiler_params[] =
{
    { "modules", Parameter::PT_TABLE, profiler_time_params, nullptr,
      "module time profiling" },

    { "memory", Parameter::PT_TABLE, profiler_memory_params, nullptr,
      "module memory profiling" },

    { "rules", Parameter::PT_TABLE, profiler_rule_params, nullptr,
      "rule time profiling" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ProfilerReloadTuner : public snort::ReloadResourceTuner
{
public:
    explicit ProfilerReloadTuner(bool enable) : enable(enable)
    {}
    ~ProfilerReloadTuner() override = default;

    bool tinit() override
    {
        RuleContext::set_enabled(enable);
        return false;
    }

    bool tune_packet_context() override
    { return true; }

    bool tune_idle_context() override
    { return true; }

private:
    bool enable = false;
};

template<typename T>
static bool s_profiler_module_set_max_depth(T& config, Value& v)
{ config.max_depth = v.get_int16(); return true; }

static bool s_profiler_module_set_max_depth(RuleProfilerConfig&, Value&)
{ return false; }

template<typename T>
static bool s_profiler_module_set(T& config, Value& v)
{
    if ( v.is("count") )
        config.count = v.get_uint32();

    else if ( v.is("show") )
        config.show = v.get_bool();

    else if ( v.is("sort") )
        config.sort = static_cast<typename T::Sort>(v.get_uint8());

    else if ( v.is("max_depth") )
        return s_profiler_module_set_max_depth(config, v);

    else
        return false;

    return true;
}

ProfilerModule::ProfilerModule() : snort::Module("profiler", profiler_help, profiler_params)
{ }

bool ProfilerModule::set(const char* fqn, Value& v, SnortConfig* sc)
{
    const char* spt = "profiler.modules";
    const char* spm = "profiler.memory";
    const char* spr = "profiler.rules";

    if ( !strncmp(fqn, spt, strlen(spt)) )
        return s_profiler_module_set(sc->profiler->time, v);

    else if ( !strncmp(fqn, spm, strlen(spm)) )
        return s_profiler_module_set(sc->profiler->memory, v);

    else if ( !strncmp(fqn, spr, strlen(spr)) )
        return s_profiler_module_set(sc->profiler->rule, v);

    return false;
}

bool ProfilerModule::end(const char* fqn, int, SnortConfig* sc)
{
    TimeProfilerStats::set_enabled(sc->profiler->time.show);
    RuleContext::set_enabled(sc->profiler->rule.show);

    if ( Snort::is_reloading() && strcmp(fqn, "profiler") == 0 )
        sc->register_reload_handler(new ProfilerReloadTuner(sc->profiler->rule.show));

    return true;
}

ProfileStats* ProfilerModule::get_profile(
    unsigned index, const char*& name, const char*& parent) const
{
    switch ( index )
    {
    case 0:
        name = "total";
        parent = nullptr;
        return &totalPerfStats;

    case 1:
        name = "other";
        parent = nullptr;
        return &otherPerfStats;
    }
    return nullptr;
}
