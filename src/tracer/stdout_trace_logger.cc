//--------------------------------------------------------------------------
// Copyright (C) 2025-2026 Cisco and/or its affiliates. All rights reserved.
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
// stdout_trace_logger.cc author Pranav Jain <ppramodj@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stdout_trace_logger.h"
#include "framework/base_api.h"
#include "main/snort_config.h"
#include "trace_loader.h"
#include "trace/trace_api.h"

#include <cstdio>
#include <cstring>

using namespace snort;

//---------------------------------------------------------------------
// Config Parameters
//---------------------------------------------------------------------
static const Parameter s_params[] =
{
    { "enable",   Parameter::PT_BOOL, nullptr, nullptr, "enable stdout trace logger" },
    { nullptr,     Parameter::PT_MAX,  nullptr, nullptr, nullptr }
};

//---------------------------------------------------------------------
// StdoutTraceModule
//---------------------------------------------------------------------
StdoutTraceModule::StdoutTraceModule() : Module(S_NAME, S_HELP, s_params)
{
    config.enable = true;
}

StdoutTraceModule::~StdoutTraceModule() = default;

bool StdoutTraceModule::set(const char* name, Value& v, SnortConfig*)
{
    if (strcmp(name, "stdout_trace.enable") == 0)
    {
        config.enable = v.get_bool();
        
        if (config.enable)
            TraceApi::register_enabled_tracer("stdout_trace");
        else
            TraceApi::unregister_tracer("stdout_trace");
    }

    return true;
}

bool StdoutTraceModule::begin(const char* fqn, int, SnortConfig*)
{
    if (!strcmp(fqn, "stdout_trace"))
    {
        config.enable = true;
    }
    return true;
}

bool StdoutTraceModule::end(const char* fqn, int, SnortConfig*)
{
    if (!strcmp(fqn, "stdout_trace"))
    {
        // Register as enabled if config.enable is true
        if (config.enable)
            TraceApi::register_enabled_tracer("stdout_trace");

        if (trace_logger_instance)
            trace_logger_instance->update_config(config);
    }
    return true;
}

const StdoutTraceConfig& StdoutTraceModule::get_config() const
{
    return config;
}

void StdoutTraceModule::register_instance(StdoutTrace* instance)
{
    trace_logger_instance = instance;
}

//---------------------------------------------------------------------
// StdoutTrace
//---------------------------------------------------------------------
StdoutTrace::StdoutTrace(const StdoutTraceConfig& cfg)
    : TraceLoggerPlug("stdout_trace"),
      config(cfg),
      file(stdout)
{   
    set_enabled(config.enable);
}

StdoutTrace::~StdoutTrace() = default;

void StdoutTrace::log(const char* log_msg, const char* name, uint8_t log_level,
    const char* trace_option, const Packet* p)
{
    if (!get_enabled())
        return;
    
    fprintf(file, "%s%c%u:%s%s:%s:%d: %s", 
        g_timestamp(get_timestamp()).c_str(),
        get_current_thread_type(),
        get_instance_id(),
        g_ntuple(get_ntuple(), p).c_str(),
        name ? name : "", trace_option ? trace_option : "", log_level, log_msg ? log_msg : "");
}

void StdoutTrace::update_config(const StdoutTraceConfig& new_config)
{
    config = new_config;
    set_enabled(config.enable);
}

//---------------------------------------------------------------------
// Plugin Lifecycle
//---------------------------------------------------------------------
static Module* mod_ctor() { return new StdoutTraceModule; }
static void mod_dtor(Module* m) { delete m; }

static TraceLoggerPlug* trace_ctor(Module* m, const std::string&)
{
    auto* mod = static_cast<StdoutTraceModule*>(m);
    StdoutTrace* logger = new StdoutTrace(mod->get_config());
    mod->register_instance(logger);
    return logger;
}

static void trace_dtor(TraceLoggerPlug* logger) { delete logger; }


static const TraceLogApi trace_api =
{
    {
        PT_TRACE,
        sizeof(TraceLogApi),
        TRACE_LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        S_HELP,
        mod_ctor,
        mod_dtor
    },
    TRACE_OUTPUT_TYPE_FLAG__TRACE,
    trace_ctor,
    trace_dtor
};

const BaseApi* stdout_trace_logger[] =
{
    &trace_api.base,
    nullptr
};

#ifdef CATCH_TEST_BUILD

#include <catch/catch.hpp>
#include <iostream>
#include <sstream>
#include <streambuf>

// Mock utility functions
std::string g_timestamp(bool enabled)
{
    return enabled ? "01/01/25-12:00:00.000000:" : "";
}

std::string g_ntuple(bool enabled, const snort::Packet* p)
{
    if (!enabled || !p) return "";
    return "192.168.1.1 8080 -> 192.168.1.2 80 6 AS=1 ";
}

char get_current_thread_type()
{
    return 'P';
}

namespace snort
{
std::unordered_set<std::string>& TraceApi::get_enabled_tracers()
{
    static std::unordered_set<std::string> mock_enabled_tracers;
    return mock_enabled_tracers;
}

// Mock Module class 
Module::Module(const char* s, const char* h) : name(s), help(h), params(nullptr), list(false) {}
Module::Module(const char* s, const char* h, const Parameter* p, bool l) : name(s), help(h), params(p), list(l) {}
PegCount Module::get_global_count(char const*) const { return 0; }
void Module::show_interval_stats(std::vector<unsigned int, std::allocator<unsigned int> >&, FILE*) {}
void Module::show_stats(){}
void Module::init_stats(bool){}
void Module::sum_stats(bool){}
void Module::reset_stats() {}
void Module::main_accumulate_stats() {}
}

class StdoutCapture 
{
private:
    std::stringstream buffer;
    std::streambuf* old_cout;

public:
    StdoutCapture() : old_cout(std::cout.rdbuf()) 
    {
        std::cout.rdbuf(buffer.rdbuf());
    }
    
    ~StdoutCapture() 
    {
        std::cout.rdbuf(old_cout);
    }
    
    std::string get_output() 
    {
        return buffer.str();
    }
    
    void clear() 
    {
        buffer.str("");
        buffer.clear();
    }
};

struct MockLoggerPacket
{
    bool has_ip() const { return true; }
    uint8_t get_ip_proto_next() const { return 6; }
};

TEST_CASE("StdoutTrace constructor with enabled config", "[StdoutTraceLogger]")
{
    StdoutTraceConfig config;
    config.enable = true;
    
    StdoutTrace logger(config);
    bool enabled = logger.get_enabled();
    CHECK(enabled);
    CHECK(logger.get_name() == "stdout_trace");
}

TEST_CASE("StdoutTrace constructor with disabled config", "[StdoutTraceLogger]")
{
    StdoutTraceConfig config;
    config.enable = false;
    
    StdoutTrace logger(config);
    bool enabled = logger.get_enabled();
    CHECK(!enabled);
}

TEST_CASE("StdoutTrace log message", "[StdoutTraceLogger]")
{
    StdoutTraceConfig config;
    config.enable = true;
    
    StdoutTrace logger(config);
    MockLoggerPacket packet;
    
    logger.log("Test message", "test_module", 1, "test_option", 
               reinterpret_cast<const Packet*>(&packet));
    
    bool enabled = logger.get_enabled();
    CHECK(enabled);
    CHECK(logger.get_name() == "stdout_trace");
}

TEST_CASE("StdoutTrace log with null message", "[StdoutTraceLogger]")
{
    StdoutTraceConfig config;
    config.enable = true;
    
    StdoutTrace logger(config);
    MockLoggerPacket packet;
    
    StdoutCapture capture;
    logger.log(nullptr, "test_module", 1, "test_option", 
               reinterpret_cast<const Packet*>(&packet));
    
    std::string output = capture.get_output();
    CHECK(output.empty());
}

TEST_CASE("StdoutTrace update config", "[StdoutTraceLogger]")
{
    StdoutTraceConfig config;
    config.enable = true;
    
    StdoutTrace logger(config);
    bool enabled = logger.get_enabled();
    CHECK(enabled);
    
    StdoutTraceConfig new_config;
    new_config.enable = false;
    logger.update_config(new_config);
    
    bool disabled = logger.get_enabled();
    CHECK(!disabled);
}

TEST_CASE("StdoutTrace disabled logger", "[StdoutTraceLogger]")
{
    StdoutTraceConfig config;
    config.enable = false;
    
    StdoutTrace logger(config);
    MockLoggerPacket packet;
    
    StdoutCapture capture;
    logger.log("Should not appear", "test_module", 1, "test_option", 
               reinterpret_cast<const Packet*>(&packet));
    
    std::string output = capture.get_output();
    CHECK(output.empty());
}

TEST_CASE("StdoutTrace edge cases", "[StdoutTraceLogger]")
{
    StdoutTraceConfig config;
    config.enable = true;
    
    StdoutTrace logger(config);
    
    logger.log("", "test_module", 1, "test_option", nullptr);
    
    std::string long_msg(1000, 'X');
    logger.log(long_msg.c_str(), "long_test", 2, "long_option", nullptr);
    
    logger.log("Test\nWith\tSpecial\rChars", "special", 3, "chars", nullptr);
    
    for (int level = 0; level <= 10; ++level) {
        logger.log("Level test", "level_module", level, "level_option", nullptr);
    }
    
    bool enabled = logger.get_enabled();
    CHECK(enabled);
}

TEST_CASE("StdoutTrace module functions", "[StdoutTraceLogger]")
{
    StdoutTraceModule module;
    
    CHECK(std::string(module.get_name()) == "stdout_trace");
    CHECK(module.get_help() != nullptr);
    
    const Parameter* params = module.get_parameters();
    CHECK(params != nullptr);
    
    Value val(true);
    bool set_result = module.set("enabled", val, nullptr);
    CHECK(set_result);
    
    bool begin_result = module.begin("stdout_trace", 0, nullptr);
    CHECK(begin_result);
    bool end_result = module.end("stdout_trace", 0, nullptr);
    CHECK(end_result);
    
    const StdoutTraceConfig& config = module.get_config();
    CHECK(config.enable == true);
}

TEST_CASE("StdoutTrace register/unregister functionality", "[StdoutTraceLogger]")
{
    StdoutTraceConfig config;
    config.enable = true;
    
    StdoutTrace* logger = new StdoutTrace(config);
    
    bool enabled1 = logger->get_enabled();
    CHECK(enabled1);
    logger->log("Test message", "test_module", 1, "test_option", nullptr);
    
    delete logger;
    
    StdoutTrace logger2(config);
    bool enabled2 = logger2.get_enabled();
    CHECK(enabled2);
    logger2.log("Second test", "test_module2", 2, "test_option2", nullptr);
}

TEST_CASE("StdoutTrace error conditions and edge cases", "[StdoutTraceLogger]")
{
    StdoutTraceConfig config_disabled;
    config_disabled.enable = false;
    StdoutTrace disabled_logger(config_disabled);
    bool disabled_enabled = disabled_logger.get_enabled();
    CHECK(!disabled_enabled);
    disabled_logger.log("Should not appear", "disabled_module", 1, "disabled_option", nullptr);
    
    StdoutTraceConfig config_enabled;
    config_enabled.enable = true;
    StdoutTrace logger(config_enabled);
    
    logger.log(nullptr, "null_module", 1, "null_option", nullptr);
    logger.log("test", nullptr, 1, "null_option", nullptr);
    logger.log("test", "module", 1, nullptr, nullptr);
    
    logger.log("", "empty_module", 1, "empty_option", nullptr);
    logger.log("test", "", 1, "empty_option", nullptr);
    logger.log("test", "module", 1, "", nullptr);
    
    std::string long_msg(10000, 'X');
    logger.log(long_msg.c_str(), "long_module", 1, "long_option", nullptr);
    
    logger.log("special test", "module\nwith\nnewlines", 1, "option\twith\ttabs", nullptr);
}

#endif
