//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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
// trace.cc author Serhii Vlasiuk <svlasiuk@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "trace.h"

#include <algorithm>

#include "framework/module.h"
#include "managers/plugin_manager.h"

using namespace snort;

static const TraceOption s_default_trace_options[] =
{
    { DEFAULT_TRACE_OPTION_NAME, DEFAULT_TRACE_OPTION_ID, "default trace options" },

    { nullptr, 0, nullptr }
};

Trace::Trace(const Module* mod) : mod_name(mod->get_name())
{
    const TraceOption* options =  get_trace_options(mod);
    size_t options_size = 0;

    while ( options->name )
    {
        option_names.emplace_back(options->name);
        ++options_size;
        ++options;
    }
    option_levels.resize(options_size, 0);
}

bool Trace::set(const std::string& trace_option_name, uint8_t trace_level, const Module* mod)
{
    const TraceOption* options = get_trace_options(mod);
    size_t size = option_levels.size();

    for ( size_t index = 0; index < size; ++index )
    {
        if ( trace_option_name == option_name(index) )
        {
            auto option_id = options[index].id;
            assert(option_id < size);
            option_levels[option_id] = trace_level;
            return true;
        }
    }
    return false;
}

const snort::TraceOption* Trace::get_trace_options(const Module* mod) const
{
    const snort::TraceOption* options = mod->get_trace_options();
    return ( options and options->name ) ? options : s_default_trace_options;
}

void Trace::set_module_trace() const
{
    const Module* mod = PluginManager::get_module(mod_name.c_str());
    assert(mod);
    mod->set_trace(this);
}

void Trace::clear()
{ std::fill(option_levels.begin(), option_levels.end(), 0); }

#ifdef CATCH_TEST_BUILD

#include "catch/catch.hpp"

Module::Module(const char* s, const char* h) : name(s), help(h), params(nullptr), list(false)
{ }

// LCOV_EXCL_START
// required to link but not hit
Module::Module(const char* s, const char* h, const Parameter* p, bool l) : name(s), help(h), params(p), list(l)
{ }

PegCount Module::get_global_count(char const*) const
{ return 0; }

void Module::show_interval_stats(std::vector<unsigned int, std::allocator<unsigned int> >&, FILE*) { }

void Module::init_stats(bool) { }
void Module::sum_stats(bool) { }
void Module::show_stats() { }
void Module::reset_stats() { }
void Module::main_accumulate_stats() { }

Module* PluginManager::get_module(char const*)
{ return nullptr; }
// LCOV_EXCL_STOP

class TraceTestModule : public Module
{
public:
    TraceTestModule(const char* name, const TraceOption* trace_options) :
        Module(name, "trace_test_help"), test_trace_options(trace_options)
    { }

    const TraceOption* get_trace_options() const override
    { return test_trace_options; }

private:
    const TraceOption* test_trace_options;
};

TEST_CASE("default option", "[Trace]")
{
    TraceOption test_trace_options(nullptr, 0, nullptr);
    TraceTestModule trace_test_module("test_trace_module", &test_trace_options);
    Trace trace(&trace_test_module);

    bool result = trace.set(DEFAULT_TRACE_OPTION_NAME, DEFAULT_TRACE_LOG_LEVEL, &trace_test_module);
    CHECK(result == true);
    CHECK(true == trace.enabled(DEFAULT_TRACE_OPTION_ID));
}

TEST_CASE("multiple options", "[Trace]")
{
    enum
    {
        TEST_TRACE_OPTION1 = 0,
        TEST_TRACE_OPTION2,
        TEST_TRACE_OPTION3,
        TEST_TRACE_OPTION4,
    };
    const TraceOption trace_values[] =
    {
        { "option1", TEST_TRACE_OPTION1, "help_option1" },
        { "option2", TEST_TRACE_OPTION2, "help_option2" },
        { "option3", TEST_TRACE_OPTION3, "help_option3" },
        { "option4", TEST_TRACE_OPTION4, "help_option4" },

        { nullptr, 0, nullptr },
    };

    TraceTestModule trace_test_module("test_trace_module", trace_values);
    Trace trace(&trace_test_module);

    bool result = trace.set("option1", DEFAULT_TRACE_LOG_LEVEL, &trace_test_module);
    CHECK(result == true);
    CHECK(true == trace.enabled(TEST_TRACE_OPTION1));

    result = trace.set("option2", DEFAULT_TRACE_LOG_LEVEL, &trace_test_module);
    CHECK(result == true);
    CHECK(true == trace.enabled(TEST_TRACE_OPTION1));
    CHECK(true == trace.enabled(TEST_TRACE_OPTION2));

    result = trace.set("option3", DEFAULT_TRACE_LOG_LEVEL, &trace_test_module);
    CHECK(result == true);
    CHECK(true == trace.enabled(TEST_TRACE_OPTION1));
    CHECK(true == trace.enabled(TEST_TRACE_OPTION2));
    CHECK(true == trace.enabled(TEST_TRACE_OPTION3));

    result = trace.set("option4", DEFAULT_TRACE_LOG_LEVEL, &trace_test_module);
    CHECK(result == true);
    CHECK(true == trace.enabled(TEST_TRACE_OPTION1));
    CHECK(true == trace.enabled(TEST_TRACE_OPTION2));
    CHECK(true == trace.enabled(TEST_TRACE_OPTION3));
    CHECK(true == trace.enabled(TEST_TRACE_OPTION4));
}

TEST_CASE("invalid option", "[Trace]")
{
    TraceOption test_trace_options(nullptr, 0, nullptr);
    TraceTestModule trace_test_module("test_trace_module", &test_trace_options);
    Trace trace(&trace_test_module);

    bool result = trace.set("invalid_option", DEFAULT_TRACE_LOG_LEVEL, &trace_test_module);
    CHECK(result == false);
}

#endif

