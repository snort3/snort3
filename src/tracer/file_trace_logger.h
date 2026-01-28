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

#include "framework/module.h"
#include "framework/tracer.h"
#include "trace_loader.h"
#include <string>
#include <cstdio>
#include <mutex>

namespace snort
{

#define S_NAME "file_trace"
#define S_HELP "file trace logger"

struct FileTraceConfig
{
    bool enable = false;
    std::string filename = "trace_output.log";
    size_t max_file_size = 10 * 1024 * 1024;  // Default 10 MB
};

class FileTrace;

class FileTraceModule : public Module
{
public:
    FileTraceModule();
    ~FileTraceModule() override;

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    const FileTraceConfig& get_config() const;
    void register_instance(FileTrace* instance);

private:
    FileTraceConfig config;
    FileTrace* trace_logger_instance = nullptr;
};

class FileTrace : public TraceLoggerPlug
{
public:
    explicit FileTrace(const FileTraceConfig& cfg);
    ~FileTrace() override;

    void log(const char* log_msg, const char* name, uint8_t log_level, 
             const char* trace_option, const Packet* p) override;
             
    void update_config(const FileTraceConfig& new_config);
    bool is_file_opened() const
    { 
        std::lock_guard<std::mutex> lock(file_mutex);
        return file_opened; 
    }


private:
    bool open_file();
    void rotate_file();
    std::string get_full_path() const;

    FileTraceConfig config;
    FILE* file = nullptr;
    bool file_opened = false;
    size_t current_file_size = 0;
    mutable std::mutex file_mutex;
};

}

extern const snort::BaseApi* file_trace_logger[];

#endif
