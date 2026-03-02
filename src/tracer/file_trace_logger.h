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
// file_trace_logger.h author Pranav Jain <ppramodj@cisco.com>

#ifndef FILE_TRACE_LOGGER_H
#define FILE_TRACE_LOGGER_H

#include <string>
#include <cstdio>

#include "framework/module.h"
#include "framework/tracer.h"
#include "log/text_log.h"

#define S_NAME "file_trace"
#define S_HELP "file trace logger"

namespace snort
{

struct FileTraceConfig
{
    size_t max_file_size = 0;
};

class FileTrace;

class FileTraceModule : public Module
{
public:
    FileTraceModule();
    ~FileTraceModule() override;

    bool set(const char*, Value&, SnortConfig*) override;

    const FileTraceConfig& get_config() const
    { return config; }

private:
    FileTraceConfig config;
};

class FileTrace : public TraceLoggerPlug
{
public:
    explicit FileTrace(const FileTraceConfig& cfg);
    ~FileTrace() override;

    void log(const char* log_msg, const char* name, uint8_t log_level, 
             const char* trace_option, const Packet* p) override;
             
private:
    TextLog* text_log;
    FileTraceConfig config;
};

}

extern const snort::BaseApi* file_trace_logger[];

#endif

