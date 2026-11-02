//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
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
// mitigator_module.cc author Oleksandr Fatieiev <ofatieie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mitigator_module.h"

#include <lua.hpp>

#include "main.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "managers/plugin_manager.h"

#include "mitigator.h"
#include "mitigator_context_processor.h"

namespace snort
{

THREAD_LOCAL SO_PUBLIC MitigatorStats mitigator_stats;

const PegInfo mitigator_pegs[] =
{
    { CountType::SUM, "signals_received", "total signals handled by mitigator" },
    { CountType::SUM, "actions_ignore", "signals mitigated with ignore action" },
    { CountType::SUM, "actions_drop", "signals mitigated with drop action" },
    { CountType::SUM, "actions_block", "signals mitigated with block action" },
    { CountType::END, nullptr, nullptr }
};

static const RuleMap mitigator_rules[] =
{
    { MITIGATOR_EVENT_SIGNAL_IGNORED, "signal mitigated, continuing packet processing" },
    { MITIGATOR_EVENT_SIGNAL_DROPPED, "signal mitigated, dropping packet" },
    { MITIGATOR_EVENT_SIGNAL_BLOCKED, "signal mitigated, blocking flow" },
    { 0, nullptr }
};

#define mitigator_help "curbs traffic processing exceptions"

static std::vector<Parameter> mitigator_modules_params = {};

static void sync_global_enabled()
{
    MitigationGlobalContext* global = MitigationContextProcessor::global_context();
    if ( !global )
        return;

    bool any_enabled = false;
    for ( const auto& name : MitigationContextProcessor::get_supported_modules() )
    {
        const auto* ctx = MitigationContextProcessor::get_module_context(std::string(name));
        if ( ctx && ctx->enabled )
        {
            any_enabled = true;
            break;
        }
    }
    global->enabled = any_enabled;
}

bool ACMitigateCrash::execute(Analyzer&)
{
    std::call_once(once, [this]() {
        if ( modules.empty() )
        {
            const auto views = MitigationContextProcessor::get_supported_modules();
            modules = std::vector<std::string>(views.begin(), views.end());
        }

        bool (*func)(const std::string&) = enabled ? mitigator_enable_module : mitigator_disable_module;
        const std::string state = enabled ? "enabled" : "disabled";
        std::string set_modules;

        for ( const auto& module : modules )
        {
            if ( !func(module) )
                LogRespond(ctrlcon, "ERROR: Could not set mitigation to %s state for: %s\n", state.c_str(), module.data());
            else
                set_modules += module + ",";
        }

        sync_global_enabled();

        LogRespond(ctrlcon, "Mitigation for (%s) is %s\n", set_modules.c_str(), state.c_str());
    });

    return true;
}

ACMitigateCrash::~ACMitigateCrash()
{
    LogMessage("== enable crash mitigator module complete\n");
}

static int set_crash_mitigator_modules(lua_State* L, bool enabled)
{
    ControlConn* ctrlconn = ControlConn::query_from_lua(L);

    int n = lua_gettop(L);
    if ( n == 0 )
    {
        main_broadcast_command(new ACMitigateCrash(ctrlconn, {}, enabled), ctrlconn);

        ctrlconn->respond("== set crash mitigator module received\n");
        return 0;
    }

    std::vector<std::string> modules;
    constexpr uint32_t max_len = 32u;

    for ( int i = 1; i <= n; ++i )
    {
        const char* module_name = lua_tostring(L, i);
        if ( !module_name )
        {
            ctrlconn->respond("ERROR: argument is not a string\n");
            continue;
        }

        modules.push_back(std::string(module_name, strnlen(module_name, max_len)));
    }

    if ( !modules.empty() )
        main_broadcast_command(new ACMitigateCrash(ctrlconn, std::move(modules), enabled), ctrlconn);

    ctrlconn->respond("== set crash mitigator module received\n");
    return 0;
}

static int enable_crash_mitigator_module(lua_State* L)
{
    return set_crash_mitigator_modules(L, true);
}

static int disable_crash_mitigator_module(lua_State* L)
{
    return set_crash_mitigator_modules(L, false);
}

const Parameter crash_mitigator_module_params[] = {
    { "module_name", Parameter::PT_STRING, nullptr, nullptr, "name of the module" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Command mitigator_cmds[] = {
    { "enable",  enable_crash_mitigator_module,  crash_mitigator_module_params, "enable crash mitigator modules"},
    { "disable", disable_crash_mitigator_module, crash_mitigator_module_params, "disable crash mitigator modules"},

    { nullptr, nullptr, nullptr, nullptr }
};

static std::string extract_module_option(const std::string& prefix_pattern, const char* fqn)
{
    std::string option_name;
    const std::string config_name(fqn);
    size_t start_pos = config_name.find(prefix_pattern);
    if ( start_pos != std::string::npos )
    {
        start_pos += prefix_pattern.size();
        size_t end_pos = config_name.find(".", start_pos);
        size_t option_len = ( end_pos != std::string::npos ) ? end_pos - start_pos
            : config_name.size() - start_pos;

        option_name = config_name.substr(start_pos, option_len);
    }
    return option_name;
}

MitigatorModule::MitigatorModule()
    : Module("mitigator", mitigator_help)
{
    generate_params();
}

void MitigatorModule::generate_params()
{
    const auto modules = MitigationContextProcessor::get_supported_modules();
    for ( const auto& module : modules )
    {
        module_ranges.emplace_back();
        auto& module_range = module_ranges.back();

        module_range.emplace_back("enabled", Parameter::PT_BOOL, nullptr, "false", "enable/disable module");
        module_range.emplace_back("abort_on", Parameter::PT_MULTI, "ignore | drop | block", nullptr,
            "abort immediately on attempted action");
        module_range.emplace_back(nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr);

        mitigator_modules_params.emplace_back(module.data(), Parameter::PT_TABLE, module_range.data(),
            nullptr, nullptr);
    }

    std::sort(mitigator_modules_params.begin(), mitigator_modules_params.end(),
        [](const Parameter& l, const Parameter& r) { return (strcmp(l.name, r.name) < 0); });

    mitigator_modules_params.emplace_back(nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr);

    static const std::vector<Parameter> mitigator_params = [&]() {
        std::vector<Parameter> params;

        params.emplace_back("modules", Parameter::PT_TABLE, mitigator_modules_params.data(), nullptr,
            "modules mitigator option");
        params.emplace_back(nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr);

        return params;
    }();

    set_params(mitigator_params.data());
}

static uint32_t parse_abort_on_flags(Value& v)
{
    uint32_t flags = 0u;
    std::string token;
    v.set_first_token();

    while ( v.get_next_token(token) )
    {
        if ( token == "ignore" )
            flags |= static_cast<uint32_t>(MitigationAction::Ignore);

        if ( token == "drop" )
            flags |= static_cast<uint32_t>(MitigationAction::Drop);

        if ( token == "block" )
            flags |= static_cast<uint32_t>(MitigationAction::Block);
    }

    return flags;
}

bool MitigatorModule::set(const char* fqn, Value& v, SnortConfig*)
{
    if ( Snort::is_reloading() )
        return true;

    if( strstr(fqn, "mitigator.modules.") == fqn )
    {
        const std::string module_name = extract_module_option("mitigator.modules.", fqn);
        MitigationModuleContext* context = MitigationContextProcessor::take_module_context(module_name);
        if ( !context )
        {
            MitigationContextProcessor::emplace_context( module_name, false );

            context = MitigationContextProcessor::take_module_context(module_name);
        }

        if ( v.is("enabled") )
        {
            context->enabled = v.get_bool();
        }
        else if ( v.is("abort_on") )
        {
            context->abort_on_flags = parse_abort_on_flags(v);
        }

        return true;
    }

    return true;
}

bool MitigatorModule::end(const char*, int level, SnortConfig*)
{
    if (level)
        return true;

    if (Snort::is_reloading())
        LogMessage("Mitigator: reload is not supported, configuration unchanged.\n");
    else
        sync_global_enabled();

    return true;
}

const Command* MitigatorModule::get_commands() const { return mitigator_cmds; }

const RuleMap* MitigatorModule::get_rules() const { return mitigator_rules; }

unsigned MitigatorModule::get_gid() const { return GID_MITIGATOR; }

const PegInfo* MitigatorModule::get_pegs() const { return mitigator_pegs; }

PegCount* MitigatorModule::get_counts() const { return reinterpret_cast<PegCount*>(const_cast<MitigatorStats*>(&mitigator_stats)); }

} // namespace snort

#ifdef UNIT_TEST
#include <optional>

#include "catch/snort_catch.h"
#include "managers/module_manager.h"

// Lua config entry points used by finalize.lua
extern "C"
{
    bool open_table(const char*, int);
    void close_table(const char*, int);
    bool set_bool(const char*, bool);
}

using namespace snort;

// cppcheck-suppress-begin comparisonOfFuncReturningBoolError ; Catch2 false positive

namespace
{

class MitigatorConfigFixture
{
public:
    MitigatorConfigFixture()
    {
        for ( const auto& name : MitigationContextProcessor::get_supported_modules() )
        {
            auto* ctx = MitigationContextProcessor::take_module_context(std::string(name));
            saved_modules.emplace_back(ctx, ctx->enabled);
        }

        saved_global = MitigationContextProcessor::global_context()->enabled;
        ModuleManager::set_config(SnortConfig::get_main_conf());
    }

    ~MitigatorConfigFixture()
    {
        ModuleManager::set_config(nullptr);

        for ( const auto& [ctx, enabled] : saved_modules )
            ctx->enabled = enabled;

        MitigationContextProcessor::global_context()->enabled = saved_global;
    }

    MitigatorConfigFixture(const MitigatorConfigFixture&) = delete;
    MitigatorConfigFixture& operator=(const MitigatorConfigFixture&) = delete;

    // isolate the module under test from contexts registered by other tests
    void prepare(const char* module, bool enabled)
    {
        for ( const auto& saved : saved_modules )
            saved.first->enabled = false;

        MitigationContextProcessor::take_module_context(module)->enabled = enabled;
        MitigationContextProcessor::global_context()->enabled = enabled;
    }

private:
    std::vector<std::pair<MitigationModuleContext*, bool>> saved_modules;
    bool saved_global = false;
};

const char* configurable_module()
{
    const Module* m = PluginManager::get_module("mitigator");
    if ( !m )
        return nullptr;

    const auto* modules = static_cast<const Parameter*>(m->get_parameters()->range);
    return modules ? modules->name : nullptr;
}

// emulates: mitigator = { modules = { <module> = { [enabled = <enabled>] } } }
void configure_module(const std::string& module, std::optional<bool> enabled)
{
    const std::string modules = "mitigator.modules";
    const std::string fqn = modules + "." + module;

    REQUIRE(open_table("mitigator", 0));
    REQUIRE(open_table(modules.c_str(), 0));
    REQUIRE(open_table(fqn.c_str(), 0));

    if ( enabled )
        CHECK(set_bool((fqn + ".enabled").c_str(), *enabled));

    close_table(fqn.c_str(), 0);
    close_table(modules.c_str(), 0);
    close_table("mitigator", 0);
}

bool module_enabled(const char* module)
{ return MitigationContextProcessor::get_module_context(module)->enabled; }

} // namespace

TEST_CASE("mitigator is disabled when not configured", "[mitigator]")
{
    create_context(MitigationConfig{ "unconfigured_default_test" });

    const auto* ctx = MitigationContextProcessor::get_module_context("unconfigured_default_test");
    REQUIRE(ctx != nullptr);
    CHECK_FALSE(ctx->enabled);

    const MitigationGlobalContext global;
    CHECK_FALSE(global.enabled);
}

TEST_CASE("mitigator config enabled option", "[mitigator]")
{
    const char* module = configurable_module();
    if ( !module )
    {
        WARN("no configurable mitigator modules");
        return;
    }

    MitigatorConfigFixture fixture;

    SECTION("empty mitigator table applies schema default false")
    {
        fixture.prepare(module, true);

        REQUIRE(open_table("mitigator", 0));
        close_table("mitigator", 0);

        CHECK_FALSE(module_enabled(module));
        CHECK_FALSE(mitigator_is_enabled());
    }

    SECTION("omitted enabled applies schema default false")
    {
        fixture.prepare(module, true);

        configure_module(module, std::nullopt);

        CHECK_FALSE(module_enabled(module));
        CHECK_FALSE(mitigator_is_enabled());
    }

    SECTION("explicit enabled true")
    {
        fixture.prepare(module, false);

        configure_module(module, true);

        CHECK(module_enabled(module));
        CHECK(mitigator_is_enabled());
    }

    SECTION("explicit enabled false")
    {
        fixture.prepare(module, true);

        configure_module(module, false);

        CHECK_FALSE(module_enabled(module));
        CHECK_FALSE(mitigator_is_enabled());
    }
}

// cppcheck-suppress-end comparisonOfFuncReturningBoolError

#endif
