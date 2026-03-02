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
// syslog_trace_logger.h author Pranav Jain <ppramodj@cisco.com>

#ifndef SYSLOG_TRACE_LOGGER_H
#define SYSLOG_TRACE_LOGGER_H

#include "framework/module.h"
#include "framework/tracer.h"

namespace snort
{

#define S_NAME "syslog_trace"
#define S_HELP "syslog trace logger"

struct SyslogTraceConfig
{
    int priority;
};

class SyslogTrace;

class SyslogTraceModule : public Module
{
public:
    SyslogTraceModule();
    ~SyslogTraceModule() override;

    bool set(const char*, Value&, SnortConfig*) override;

    const SyslogTraceConfig& get_config() const;

private:
    SyslogTraceConfig config;
};

class SyslogTrace : public TraceLoggerPlug
{
public:
    explicit SyslogTrace(const SyslogTraceConfig& cfg);
    ~SyslogTrace() override;

    void log(const char* log_msg, const char* name, uint8_t log_level, 
             const char* trace_option, const Packet* p) override;
             
    void update_config(const SyslogTraceConfig& new_config);

private:
    SyslogTraceConfig config;
};

}

#endif

