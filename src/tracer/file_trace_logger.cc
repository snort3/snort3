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
// file_trace_logger.cc author Pranav Jain <ppramodj@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_trace_logger.h"

#include "framework/pig_pen.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "trace/trace_api.h"

using namespace snort;

#define TRACE_FILE_NAME "snort_trace.log"
#define BUFFER_SIZE 4096

//---------------------------------------------------------------------
// Config Parameters
//---------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "max_file_size", Parameter::PT_INT, "0:", "0", "maximum file size in bytes (0=unlimited)" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

//---------------------------------------------------------------------
// FileTraceModule
//---------------------------------------------------------------------

FileTraceModule::FileTraceModule() : Module(S_NAME, S_HELP, s_params) { }
FileTraceModule::~FileTraceModule() = default;

bool FileTraceModule::set(const char*, Value& v, SnortConfig*)
{
    assert(v.is("max_file_size"));
    config.max_file_size = v.get_size();
    return true;
}

//---------------------------------------------------------------------
// FileTrace
//---------------------------------------------------------------------

FileTrace::FileTrace(const FileTraceConfig& cfg) :
    TraceLoggerPlug("file_trace"),
    config(cfg)
{
    bool crit = !PigPen::snort_started();
    text_log = TextLog_Init(TRACE_FILE_NAME, BUFFER_SIZE, config.max_file_size, crit);
}

FileTrace::~FileTrace()
{
    TextLog_Term(text_log);
}

void FileTrace::log(const char* log_msg, const char* name, uint8_t log_level,
    const char* trace_option, const Packet* p)
{
    std::string timestamp_str = print_timestamp();
    char thread_type = get_thread_type();
    unsigned instance_id = get_instance_id();
    std::string ntuple_str = print_ntuple(p);

    TextLog_Print(text_log,
        "%s%c%u:%s%s:%s:%d: %s",
        timestamp_str.c_str(),
        thread_type,
        instance_id,
        ntuple_str.c_str(),
        name ? name : "", trace_option ? trace_option : "", log_level, log_msg);
}

//---------------------------------------------------------------------
// Plugin Lifecycle
//---------------------------------------------------------------------

static Module* mod_ctor() { return new FileTraceModule; }
static void mod_dtor(Module* m) { delete m; }

static TraceLoggerPlug* trace_ctor(Module* m, const std::string&)
{
    auto* mod = static_cast<FileTraceModule*>(m);
    return new FileTrace(mod->get_config());
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
const BaseApi* file_trace_logger[] =
#endif
{
    &trace_api.base,
    nullptr
};

