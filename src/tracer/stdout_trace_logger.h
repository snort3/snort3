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
// stdout_trace_logger.h author Pranav Jain <ppramodj@cisco.com>

#ifndef STDOUT_TRACE_LOGGER_H
#define STDOUT_TRACE_LOGGER_H

#include "framework/module.h"
#include "framework/tracer.h"

#define S_NAME "stdout_trace"
#define S_HELP "trace logger that prints to stdout"

namespace snort
{

class StdoutTrace : public TraceLoggerPlug
{
public:
    explicit StdoutTrace();
    ~StdoutTrace() override;

    void log(const char* log_msg, const char* name, uint8_t log_level, 
             const char* trace_option, const Packet* p) override;

private:
    FILE* file;
};

class StdoutTraceModule : public Module
{
public:
    StdoutTraceModule();
    ~StdoutTraceModule() override;
};

}

#endif

