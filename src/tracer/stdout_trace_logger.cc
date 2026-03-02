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

#include <cstdio>

#include "main/snort_config.h"
#include "trace/trace_api.h"

using namespace snort;

//---------------------------------------------------------------------
// StdoutTraceModule
//---------------------------------------------------------------------

StdoutTraceModule::StdoutTraceModule() : Module(S_NAME, S_HELP) { }
StdoutTraceModule::~StdoutTraceModule() = default;

//---------------------------------------------------------------------
// StdoutTrace
//---------------------------------------------------------------------

StdoutTrace::StdoutTrace() : TraceLoggerPlug(S_NAME), file(stdout) { }

StdoutTrace::~StdoutTrace() = default;

void StdoutTrace::log(const char* log_msg, const char* name, uint8_t log_level,
    const char* trace_option, const Packet* p)
{
    fprintf(file, "%s%c%u:%s%s:%s:%d: %s", 
        print_timestamp().c_str(),
        get_thread_type(),
        get_instance_id(),
        print_ntuple(p).c_str(),
        name ? name : "", trace_option ? trace_option : "", log_level, log_msg ? log_msg : "");
}

//---------------------------------------------------------------------
// Plugin Lifecycle
//---------------------------------------------------------------------

static Module* mod_ctor() { return new StdoutTraceModule; }
static void mod_dtor(Module* m) { delete m; }

static TraceLoggerPlug* trace_ctor(Module*, const std::string&)
{ return new StdoutTrace; }

static void trace_dtor(TraceLoggerPlug* logger)
{ delete logger; }


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
const BaseApi* stdout_trace_logger[] =
#endif
{
    &trace_api.base,
    nullptr
};

