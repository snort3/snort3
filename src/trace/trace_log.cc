//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// trace_log.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "trace_log.h"

#include <cstdio>
#include <syslog.h>

using namespace snort;

//-----------------------------------------------
//  Loggers
//-----------------------------------------------

// Stdout

class StdoutTraceLogger : public TraceLogger
{
public:
    StdoutTraceLogger();

    void log(const char* log_msg, const char* name,
        uint8_t log_level, const char* trace_option, const Packet* p) override;

private:
    FILE* file;
};

StdoutTraceLogger::StdoutTraceLogger()
    : file(stdout)
{ }

void StdoutTraceLogger::log(const char* log_msg, const char* name,
    uint8_t log_level, const char* trace_option, const Packet*)
{
    fprintf(file, "%s:%s:%d: %s", name, trace_option, log_level, log_msg);
}

// Syslog

class SyslogTraceLogger : public TraceLogger
{
public:
    SyslogTraceLogger();

    void log(const char* log_msg, const char* name,
        uint8_t log_level, const char* trace_option, const Packet* p) override;

private:
    int priority;
};

SyslogTraceLogger::SyslogTraceLogger()
    : priority(LOG_DAEMON | LOG_DEBUG)
{ }

void SyslogTraceLogger::log(const char* log_msg, const char* name,
    uint8_t log_level, const char* trace_option, const Packet*)
{
    syslog(priority, "%s:%s:%d: %s", name, trace_option, log_level, log_msg);
}

//-----------------------------------------------
//  Logger factories
//-----------------------------------------------

// Stdout

TraceLogger* StdoutLoggerFactory::instantiate()
{
    return new StdoutTraceLogger();
}

// Syslog

TraceLogger* SyslogLoggerFactory::instantiate()
{
    return new SyslogTraceLogger();
}

