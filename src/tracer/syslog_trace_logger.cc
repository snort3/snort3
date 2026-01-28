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
// syslog_trace_logger.cc author Pranav Jain <ppramodj@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syslog_trace_logger.h"
#include "main/snort_config.h"
#include "framework/base_api.h"
#include "trace/trace_api.h"
#include "trace_loader.h"

#include <cstdio>
#include <cstring>
#include <syslog.h>

using namespace snort;

//---------------------------------------------------------------------
// Config Parameters
//---------------------------------------------------------------------
static int get_priority(const char* s)
{
    if (!strcmp(s, "emerg")) return LOG_EMERG;
    if (!strcmp(s, "alert")) return LOG_ALERT;
    if (!strcmp(s, "crit")) return LOG_CRIT;
    if (!strcmp(s, "err")) return LOG_ERR;
    if (!strcmp(s, "warning")) return LOG_WARNING;
    if (!strcmp(s, "notice")) return LOG_NOTICE;
    if (!strcmp(s, "info")) return LOG_INFO;
    if (!strcmp(s, "debug")) return LOG_DEBUG;
    return LOG_INFO;
}

static const Parameter syslog_params[] =
{
    { "enable", Parameter::PT_BOOL, nullptr, nullptr, "enable syslog trace logger" },
    { "priority", Parameter::PT_ENUM, "emerg | alert | crit | err | warning | notice | info | debug", 
      "info", "select syslog priority" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//---------------------------------------------------------------------
// SyslogTraceModule
//---------------------------------------------------------------------
SyslogTraceModule::SyslogTraceModule() : Module(S_NAME, S_HELP, syslog_params)
{
    config.enable = true;
    config.priority = LOG_INFO;
}

SyslogTraceModule::~SyslogTraceModule() = default;

bool SyslogTraceModule::set(const char* name, Value& v, SnortConfig*)
{
    if (strcmp(name, "syslog_trace.enable") == 0)
    {
        config.enable = v.get_bool();
        
        if (config.enable)
            TraceApi::register_enabled_tracer("syslog_trace");
        else
            TraceApi::unregister_tracer("syslog_trace");
    }
    else if (strcmp(name, "syslog_trace.priority") == 0)
        config.priority = get_priority(v.get_string());

    return true;
}

bool SyslogTraceModule::begin(const char* fqn, int, SnortConfig*)
{
    if (!strcmp(fqn, "syslog_trace"))
    {
        config.enable = true;
        config.priority = LOG_INFO;
    }
    return true;
}

bool SyslogTraceModule::end(const char* fqn, int, SnortConfig*)
{
    if (!strcmp(fqn, "syslog_trace"))
    {
        // Register as enabled if config.enable is true
        if (config.enable)
            TraceApi::register_enabled_tracer("syslog_trace");

        if (trace_logger_instance)
            trace_logger_instance->update_config(config);
    }
    return true;
}

const SyslogTraceConfig& SyslogTraceModule::get_config() const
{
    return config;
}

void SyslogTraceModule::register_instance(SyslogTrace* instance)
{
    trace_logger_instance = instance;
}

//---------------------------------------------------------------------
// SyslogTrace
//---------------------------------------------------------------------
SyslogTrace::SyslogTrace(const SyslogTraceConfig& cfg)
    : TraceLoggerPlug("syslog_trace"),
      config(cfg),
      syslog_opened(false)
{
    if (config.enable)
    {
        openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON);
        syslog_opened = true;
    }

    set_enabled(config.enable);
}

SyslogTrace::~SyslogTrace()
{
    if (syslog_opened)
    {
        closelog();
    }
}

void SyslogTrace::log(const char* log_msg, const char* name, uint8_t log_level,
    const char* trace_option, const Packet* p)
{
    if (!get_enabled() || !syslog_opened)
        return;
    
    syslog(config.priority, "%c%u:%s%s:%s:%d: %s", get_current_thread_type(),
        get_instance_id(), g_ntuple(get_ntuple(), p).c_str(),
        name, trace_option, log_level, log_msg);
}

void SyslogTrace::update_config(const SyslogTraceConfig& new_config)
{
    bool was_enabled = config.enable;
    config = new_config;
    
    if (config.enable && !was_enabled && !syslog_opened)
    {
        openlog("snort", LOG_PID | LOG_CONS, LOG_DAEMON);
        syslog_opened = true;
    }
    else if (!config.enable && was_enabled && syslog_opened)
    {
        closelog();
        syslog_opened = false;
    }
    else if (config.enable && syslog_opened)
    {
        closelog();
        openlog("snort",LOG_PID | LOG_CONS, LOG_DAEMON);
    }
    
    set_enabled(config.enable);
}

//---------------------------------------------------------------------
// Plugin Lifecycle
//---------------------------------------------------------------------
static Module* mod_ctor() { return new SyslogTraceModule; }
static void mod_dtor(Module* m) { delete m; }

static TraceLoggerPlug* trace_ctor(Module* m, const std::string&)
{
    auto* mod = static_cast<SyslogTraceModule*>(m);
    const SyslogTraceConfig& config = mod->get_config();
    SyslogTrace* logger = new SyslogTrace(config);
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

const BaseApi* syslog_trace_logger[] =
{
    &trace_api.base,
    nullptr
};

#ifdef CATCH_TEST_BUILD

#include <catch/catch.hpp>

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

// Mock snort namespace functions
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

static bool mock_syslog_opened = false;
static int last_priority = -1;
static std::string last_message;

// Mock syslog functions
extern "C" {
void openlog(const char*, int, int) {
    mock_syslog_opened = true;
}

void syslog(int priority, const char* format, ...) {
    last_priority = priority;
    last_message = format;
}

void closelog(void) {
    mock_syslog_opened = false;
}
}

struct MockSyslogPacket
{
    bool has_ip() const { return true; }
    uint8_t get_ip_proto_next() const { return 6; }
};

TEST_CASE("SyslogTrace constructor with enabled config", "[SyslogTraceLogger]")
{
    SyslogTraceConfig config;
    config.enable = true;
    config.priority = LOG_INFO;
    
    SyslogTrace logger(config);
    bool enabled = logger.get_enabled();
    CHECK(enabled);
    CHECK(logger.get_name() == "syslog_trace");
    CHECK(mock_syslog_opened);
}

TEST_CASE("SyslogTrace constructor with disabled config", "[SyslogTraceLogger]")
{
    SyslogTraceConfig config;
    config.enable = false;
    config.priority = LOG_INFO;
    
    mock_syslog_opened = false;
    SyslogTrace logger(config);
    bool enabled = logger.get_enabled();
    CHECK(!enabled);
    CHECK(!mock_syslog_opened);
}

TEST_CASE("SyslogTrace log message", "[SyslogTraceLogger]")
{
    SyslogTraceConfig config;
    config.enable = true;
    config.priority = LOG_INFO;
    
    SyslogTrace logger(config);
    MockSyslogPacket packet;
    
    last_priority = -1;
    logger.log("Test syslog message", "test_module", 1, "test_option", 
               reinterpret_cast<const Packet*>(&packet));
    
    CHECK(last_priority == LOG_INFO);
}

TEST_CASE("SyslogTrace update config enable", "[SyslogTraceLogger]")
{
    SyslogTraceConfig config;
    config.enable = false;
    config.priority = LOG_INFO;
    
    mock_syslog_opened = false;
    SyslogTrace logger(config);
    bool disabled = logger.get_enabled();
    CHECK(!disabled);
    CHECK(!mock_syslog_opened);
    
    SyslogTraceConfig new_config;
    new_config.enable = true;
    new_config.priority = LOG_WARNING;
    logger.update_config(new_config);
    
    bool enabled = logger.get_enabled();
    CHECK(enabled);
    CHECK(mock_syslog_opened);
}

TEST_CASE("SyslogTrace update config disable", "[SyslogTraceLogger]")
{
    SyslogTraceConfig config;
    config.enable = true;
    config.priority = LOG_INFO;
    
    SyslogTrace logger(config);
    bool enabled = logger.get_enabled();
    CHECK(enabled);
    CHECK(mock_syslog_opened);
    
    SyslogTraceConfig new_config;
    new_config.enable = false;
    new_config.priority = LOG_INFO;
    logger.update_config(new_config);
    
    bool disabled = logger.get_enabled();
    CHECK(!disabled);
    CHECK(!mock_syslog_opened);
}



TEST_CASE("SyslogTrace different priorities", "[SyslogTraceLogger]")
{
    std::vector<int> priorities = {LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, 
                                  LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG};
    
    for (int priority : priorities) {
        SyslogTraceConfig config;
        config.enable = true;
        config.priority = priority;
        
        SyslogTrace logger(config);
        logger.log("Priority test", "priority_module", 1, "priority_option", nullptr);
        CHECK(last_priority == priority);
        
        last_priority = -1;
        mock_syslog_opened = false;
    }
}

TEST_CASE("SyslogTrace edge cases", "[SyslogTraceLogger]")
{
    SyslogTraceConfig config;
    config.enable = true;
    config.priority = LOG_INFO;
    
    SyslogTrace logger(config);
    
    logger.log("", "empty_module", 1, "empty_option", nullptr);
    CHECK(last_priority == LOG_INFO);
    
    std::string long_msg(2000, 'A');
    logger.log(long_msg.c_str(), "long_module", 1, "long_option", nullptr);
    CHECK(last_priority == LOG_INFO);
    
    logger.log("Special\nChars\tTest\r", "special_module", 1, "special_option", nullptr);
    CHECK(last_priority == LOG_INFO);
    
    logger.log("Null packet test", "null_module", 1, "null_option", nullptr);
    CHECK(last_priority == LOG_INFO);
}

TEST_CASE("SyslogTrace module functions", "[SyslogTraceLogger]")
{
    SyslogTraceModule module;
    
    CHECK(std::string(module.get_name()) == "syslog_trace");
    CHECK(module.get_help() != nullptr);
    
    const Parameter* params = module.get_parameters();
    CHECK(params != nullptr);
    
    Value val_enabled(true);
    Value val_priority(static_cast<int64_t>(LOG_DEBUG));
    
    bool set_enabled = module.set("enabled", val_enabled, nullptr);
    CHECK(set_enabled);
    bool set_priority = module.set("priority", val_priority, nullptr);
    CHECK(set_priority);

    bool begin = module.begin("syslog_trace", 0, nullptr);
    CHECK(begin);
    bool end = module.end("syslog_trace", 0, nullptr);
    CHECK(end);

    const SyslogTraceConfig& config = module.get_config();
    CHECK(config.enable == true);
}

TEST_CASE("SyslogTrace register/unregister functionality", "[SyslogTraceLogger]")
{
    SyslogTraceConfig config;
    config.enable = true;
    config.priority = static_cast<int64_t>(LOG_INFO);
    
    SyslogTrace* logger = new SyslogTrace(config);

    bool enabled = logger->get_enabled();
    CHECK(enabled);
    logger->log("Test message", "test_module", 1, "test_option", nullptr);
    
    delete logger;
    
    SyslogTrace logger2(config);
    bool enabled1 = logger2.get_enabled();
    CHECK(enabled1);
    logger2.log("Second test", "test_module2", 2, "test_option2", nullptr);
}

TEST_CASE("SyslogTrace auto-enable on configuration", "[SyslogTraceLogger]")
{
    SyslogTraceModule module;
    
    // Simulate configuration block being encountered (like syslog_trace = {})
    bool begin_result = module.begin("syslog_trace", 0, nullptr);
    CHECK(begin_result);
    
    // After begin(), the module should be auto-enabled
    const SyslogTraceConfig& config = module.get_config();
    CHECK(config.enable == true);
    CHECK(config.priority == LOG_INFO);
    
    // End should work normally
    bool end_result = module.end("syslog_trace", 0, nullptr);
    CHECK(end_result);
}

#endif
