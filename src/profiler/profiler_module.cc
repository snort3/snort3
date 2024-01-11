//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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
#include "lua/lua.h"
#include "main/analyzer_command.h"
#include "main/reload_tuner.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"
#include "utils/stats.h"

#include "rule_profiler.h"
#include "rule_profiler_defs.h"
#include "time_profiler.h"
#include "time_profiler_defs.h"

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
    ProfilerRuleDump(ControlConn* conn, OutType out_type)
        : AnalyzerCommand(conn), nodes(), stats(), out_type(out_type)
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

        RuleContext::set_end_time(get_time_curr());
        print_rule_profiler_stats(config->rule, stats, ctrlcon, out_type);
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
    OutType out_type;
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
    RuleContext::set_start_time(get_time_curr());
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
    RuleContext::set_end_time(get_time_curr());
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

    const int num_of_args = lua_gettop(L);

    if (!L or (num_of_args == 0))
    {
        main_broadcast_command(new ProfilerRuleDump(ctrlcon, OutType::OUTPUT_TABLE), ctrlcon);
        return 0;
    }

    if (num_of_args > 1)
    {
        LogRespond(ctrlcon, "Too many arguments for rule_dump(output) command\n");
        return 0;
    }

    const char* arg = lua_tostring(L, 1);

    if (strcmp(arg, "json") == 0)
        main_broadcast_command(new ProfilerRuleDump(ctrlcon, OutType::OUTPUT_JSON), ctrlcon);

    else if (strcmp(arg, "table") == 0)
        main_broadcast_command(new ProfilerRuleDump(ctrlcon, OutType::OUTPUT_TABLE), ctrlcon);

    else
        LogRespond(ctrlcon, "Invalid usage of rule_dump(output), argument can be 'table' or 'json'\n");

    return 0;
}

static const Parameter profiler_dump_params[] =
{
    { "output", Parameter::PT_ENUM, "table | json",
      "table", "output format for rule statistics" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static void time_profiling_start_cmd()
{
    // Because profiler is always started in Analyzer::operator()
    Profiler::stop(0);
    TimeProfilerStats::set_enabled(true);
    Profiler::reset_stats(snort::PROFILER_TYPE_TIME);
    Profiler::start();
}

static void time_profiling_stop_cmd()
{
    TimeProfilerStats::set_enabled(false);
    Profiler::stop((uint64_t)get_packet_number());
    Profiler::consolidate_stats(snort::PROFILER_TYPE_TIME);
}

class ProfilerTimeCmd : public AnalyzerCommand
{
public:
    ProfilerTimeCmd(bool en) : enable(en) { }
    bool execute(Analyzer&, void**) override
    {
        if ( enable )
            time_profiling_start_cmd();
        else
            time_profiling_stop_cmd();

        return true;
    }
    const char* stringify() override { return "TIME_PROFILING"; }
private:
    bool enable;
};

static int time_profiling_start(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    if ( TimeProfilerStats::is_enabled() )
    {
        LogRespond(ctrlcon, "Time profiling is already started.\n");
        return 0;
    }
    Profiler::reset_stats(snort::PROFILER_TYPE_TIME);
    TimeProfilerStats::set_enabled(true);
    main_broadcast_command(new ProfilerTimeCmd(true), ctrlcon);
    LogRespond(ctrlcon, "Time profiling is started.\n");
    return 0;
}

static int time_profiling_stop(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    if ( !TimeProfilerStats::is_enabled() )
    {
        LogRespond(ctrlcon, "Time profiling is not started.\n");
        return 0;
    }

    TimeProfilerStats::set_enabled(false);
    main_broadcast_command(new ProfilerTimeCmd(false), ctrlcon);
    LogRespond(ctrlcon, "Time profiling is stopped.\n");
    return 0;
}

static int time_profiling_dump(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);
    if ( TimeProfilerStats::is_enabled() )
    {
        LogRespond(ctrlcon, "Time profiling is still running.\n");
        return 0;
    }

    Profiler::prepare_stats();

    const auto* config = SnortConfig::get_conf()->get_profiler();
    assert(config);

    print_time_profiler_stats(Profiler::get_profiler_nodes(), config->time, ctrlcon);

    return 0;
}

static int time_profiling_status(lua_State* L)
{
    ControlConn* ctrlcon = ControlConn::query_from_lua(L);

    if ( TimeProfilerStats::is_enabled() )
        LogRespond(ctrlcon, "Time profiling is enabled.\n");
    else
        LogRespond(ctrlcon, "Time profiling is disabled.\n");

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
      profiler_dump_params, "print rule statistics in table or json format (json format prints dates as Unix epoch)" },

    { "module_start", time_profiling_start,
      nullptr, "enable module time profiling" },

    { "module_stop", time_profiling_stop,
      nullptr, "disable module time profiling" },

    { "module_dump", time_profiling_dump,
      nullptr, "print module time profiling statistics" },

    { "module_status", time_profiling_status,
      nullptr, "show module time profiler status" },

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

    { "dump_file_size", Parameter::PT_INT, "4096:max53", "1073741824",
      "files will be rolled over if they exceed this size" },

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
    explicit ProfilerReloadTuner(bool enable_rule, bool enable_time) 
        : enable_rule(enable_rule), enable_time(enable_time)
    {}
    ~ProfilerReloadTuner() override = default;

    bool tinit() override
    {
        RuleContext::set_enabled(enable_rule);

        if ( enable_time && !TimeProfilerStats::is_enabled() )
            time_profiling_start_cmd();

        else if ( !enable_time && TimeProfilerStats::is_enabled() )
            time_profiling_stop_cmd();

        return false;
    }

    bool tune_packet_context() override
    { return true; }

    bool tune_idle_context() override
    { return true; }

private:
    bool enable_rule = false;
    bool enable_time = false;
};

template<typename T>
static bool s_profiler_module_set_max_depth(T& config, Value& v)
{ config.max_depth = v.get_int16(); return true; }

static bool s_profiler_module_set_max_depth(RuleProfilerConfig&, Value&)
{ return false; }

template<typename T>
static bool s_profiler_module_set_dump_file_size(T&, Value&)
{ return false; }

// cppcheck-suppress constParameter
static bool s_profiler_module_set_dump_file_size(MemoryProfilerConfig& config, Value& v)
{ config.dump_file_size = v.get_int64(); return true; }

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

    else if ( v.is("dump_file_size") )
        return s_profiler_module_set_dump_file_size(config, v);

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

    if ( sc->profiler->rule.show )
        RuleContext::set_start_time(get_time_curr());

    if ( Snort::is_reloading() && strcmp(fqn, "profiler") == 0 )
        sc->register_reload_handler(new ProfilerReloadTuner(sc->profiler->rule.show,
            sc->profiler->time.show));

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
