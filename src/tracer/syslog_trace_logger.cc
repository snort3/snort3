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

#include <syslog.h>

#include "framework/pig_pen.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "trace/trace_api.h"

using namespace snort;

//---------------------------------------------------------------------
// Config Parameters
//---------------------------------------------------------------------

static int get_priority(unsigned lvl)
{
    switch ( lvl )
    {
    case 0: return LOG_EMERG;
    case 1: return LOG_ALERT;
    case 2: return LOG_CRIT;
    case 3: return LOG_ERR;
    case 4: return LOG_WARNING;
    case 5: return LOG_NOTICE;
    case 7: return LOG_DEBUG;
    }
    assert(lvl == 6);
    return LOG_INFO;
}

static const Parameter syslog_params[] =
{
    { "priority", Parameter::PT_ENUM, "emerg | alert | crit | err | warning | notice | info | debug", 
      "info", "select syslog priority" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//---------------------------------------------------------------------
// SyslogTraceModule
//---------------------------------------------------------------------

SyslogTraceModule::SyslogTraceModule() : Module(S_NAME, S_HELP, syslog_params)
{ config.priority = LOG_INFO; }

SyslogTraceModule::~SyslogTraceModule() = default;

bool SyslogTraceModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("priority"));
    config.priority = get_priority(v.get_uint8());
    return true;
}

const SyslogTraceConfig& SyslogTraceModule::get_config() const
{
    return config;
}

//---------------------------------------------------------------------
// SyslogTrace
//---------------------------------------------------------------------

SyslogTrace::SyslogTrace(const SyslogTraceConfig& cfg) :
    TraceLoggerPlug("syslog_trace"),
    config(cfg)
{
    if ( in_main_thread() )
        PigPen::open_syslog();
}

SyslogTrace::~SyslogTrace()
{
    if ( in_main_thread() )
        PigPen::close_syslog();
}

void SyslogTrace::log(const char* log_msg, const char* name, uint8_t log_level,
    const char* trace_option, const Packet* p)
{
    syslog(config.priority, "%c%u:%s%s:%s:%d: %s", get_thread_type(),
        get_instance_id(), print_ntuple(p).c_str(),
        name, trace_option, log_level, log_msg);
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
        PLUGIN_SO_RELOAD,
        API_OPTIONS,
        S_NAME,
        S_HELP,
        mod_ctor,
        mod_dtor
    },
    TRACER_FLAG__RESERVED,
    trace_ctor,
    trace_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* syslog_trace_logger[] =
#endif
{
    &trace_api.base,
    nullptr
};

