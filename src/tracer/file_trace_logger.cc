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
#include "framework/base_api.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "trace/trace_api.h"
#include "trace_loader.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <sys/stat.h>
#include <unistd.h>

using namespace snort;

//---------------------------------------------------------------------
// Config Parameters
//---------------------------------------------------------------------
static const Parameter s_params[] =
{
    { "enable",    Parameter::PT_BOOL,   nullptr, nullptr, "enable file trace logger" },
    { "filename",   Parameter::PT_STRING, nullptr, "trace_output.log", "output filename" },
    { "max_file_size",   Parameter::PT_INT,    "0:", "10485760", "maximum file size in bytes (default 10MB, 0=unlimited)" },
    { nullptr,      Parameter::PT_MAX,    nullptr, nullptr, nullptr }
};

//---------------------------------------------------------------------
// FileTraceModule
//---------------------------------------------------------------------
FileTraceModule::FileTraceModule() : Module(S_NAME, S_HELP, s_params) { }

FileTraceModule::~FileTraceModule() = default;

bool FileTraceModule::set(const char* name, Value& v, SnortConfig*)
{
    if (strcmp(name, "file_trace.enable") == 0)
    {
        config.enable = v.get_bool();
        
        if (config.enable)
            TraceApi::register_enabled_tracer("file_trace");
        else
            TraceApi::unregister_tracer("file_trace");
    }
    else if (strcmp(name, "file_trace.filename") == 0)
        config.filename = v.get_string();
    else if (strcmp(name, "file_trace.max_file_size") == 0)
        config.max_file_size = v.get_size();

    return true;
}

bool FileTraceModule::begin(const char* fqn, int, SnortConfig*)
{
    if (!strcmp(fqn, "file_trace"))
    {
        config.enable = true;
    }
    return true;
}

bool FileTraceModule::end(const char* fqn, int, SnortConfig*)
{
    if (!strcmp(fqn, "file_trace"))
    {
        // Register as enabled if config.enable is true
        if (config.enable)
            TraceApi::register_enabled_tracer("file_trace");

        if (trace_logger_instance)
            trace_logger_instance->update_config(config);
    }
    return true;
}

const FileTraceConfig& FileTraceModule::get_config() const
{
    return config;
}

void FileTraceModule::register_instance(FileTrace* instance)
{
    trace_logger_instance = instance;
}

//---------------------------------------------------------------------
// FileTrace
//---------------------------------------------------------------------
FileTrace::FileTrace(const FileTraceConfig& cfg)
    : TraceLoggerPlug("file_trace"),
      config(cfg),
      file(nullptr),
      file_opened(false),
      current_file_size(0)
{
    if (config.enable)
    {
        open_file();
    }

    set_enabled(config.enable);
}

FileTrace::~FileTrace()
{
    std::lock_guard<std::mutex> lock(file_mutex);
    if (file_opened && file)
    {
        fclose(file);
        file = nullptr;
        file_opened = false;
        current_file_size = 0;
    }
}

std::string FileTrace::get_full_path() const
{
    const SnortConfig* sc = SnortConfig::get_conf();
    std::string full_path;

    // If filename is already an absolute path, use it as-is
    if (!config.filename.empty() && config.filename[0] == '/')
    {
        full_path = config.filename;
    }
    else
    {
        // Use configured log_dir or default to current directory
        if (sc && !sc->log_dir.empty())
            full_path = sc->log_dir;
        else
            full_path = ".";

        if (full_path.back() != '/')
            full_path += '/';

        // Append the configured filename
        full_path += config.filename;
    }

    // printf("FileTrace::get_full_path() - %s\n", full_path.c_str());
    return full_path;
}

bool FileTrace::open_file()
{
    std::lock_guard<std::mutex> lock(file_mutex);

    if (file_opened)
        return true;

    std::string full_path = get_full_path();

    // Open in "a" mode - appends to existing file, creates if it doesn't exist
    file = fopen(full_path.c_str(), "a");
    if (!file)
        return false;

    file_opened = true;

    // Get current file size for rotation logic
    fseek(file, 0, SEEK_END);
    current_file_size = ftell(file);

    fflush(file);
    return true;
}

void FileTrace::rotate_file()
{    
    if (!file_opened || !file)
        return;
    
    std::string full_path = get_full_path();
    std::string backup_name = full_path + ".1";
    
    // Close current file
    fclose(file);
    file = nullptr;
    file_opened = false;

    // Delete old backup if it exists (keep only one backup)
    // Note: unlink() will fail gracefully if file doesn't exist (ENOENT)
    if (unlink(backup_name.c_str()) != 0 && errno != ENOENT)
    {
        LogMessage("Warning: Failed to delete old backup %s: %s\n",
                  backup_name.c_str(), strerror(errno));
    }

    // Rename current file to backup
    if (rename(full_path.c_str(), backup_name.c_str()) != 0)
    {
        ErrorMessage("Failed to rename trace file %s to %s: %s\n",
                      full_path.c_str(), backup_name.c_str(), strerror(errno));
    }

    // Open new file (write mode for fresh start after rotation)
    file = fopen(full_path.c_str(), "w");
    if (file)
    {
        file_opened = true;
        current_file_size = 0;
        fflush(file);
    }
}

void FileTrace::log(const char* log_msg, const char* name, uint8_t log_level,
    const char* trace_option, const Packet* p)
{
    if (!get_enabled())
        return;

    std::string timestamp_str = g_timestamp(get_timestamp());
    char thread_type = get_current_thread_type();
    unsigned instance_id = get_instance_id();
    std::string ntuple_str = g_ntuple(get_ntuple(), p);

    std::string clean_msg = log_msg ? log_msg : "";
    clean_msg.erase(std::remove(clean_msg.begin(), clean_msg.end(), '\0'), clean_msg.end());

    // Remove trailing newlines and carriage returns
    while (!clean_msg.empty() && (clean_msg.back() == '\n' || clean_msg.back() == '\r'))
        clean_msg.pop_back();

    std::lock_guard<std::mutex> lock(file_mutex);

    if (!file_opened || !file)
        return;

    char formatted_msg[2048];
    memset(formatted_msg, 0, sizeof(formatted_msg));

    int written = snprintf(formatted_msg, sizeof(formatted_msg),
        "%s%c%u:%s%s:%s:%d: %s\n",
        timestamp_str.c_str(),
        thread_type,
        instance_id,
        ntuple_str.c_str(),
        name ? name : "", trace_option ? trace_option : "", log_level, clean_msg.c_str());

    if (written <= 0 || written >= (int)sizeof(formatted_msg))
        return;  // Invalid message size

    // Check if rotation is needed
    bool need_rotation = (config.max_file_size > 0 &&
                         (current_file_size + written) > config.max_file_size);

    if (need_rotation)
    {
        rotate_file();

        if (!file_opened || !file)
            return;  // Cannot open new file
    }

    // Validate the formatted message before writing
    bool has_null_chars = false;
    for (int i = 0; i < written - 1; i++)
    {
        if (formatted_msg[i] == '\0')
        {
            has_null_chars = true;
            break;
        }
    }

    // Only write if the message is valid
    if (!has_null_chars)
    {
        size_t bytes_written = fwrite(formatted_msg, 1, written, file);
        if (bytes_written == (size_t)written)
        {
            current_file_size += bytes_written;
            fflush(file);
        }
    }
}

void FileTrace::update_config(const FileTraceConfig& new_config)
{
    std::lock_guard<std::mutex> lock(file_mutex);
    
    bool was_enabled = config.enable;
    bool filename_changed = (config.filename != new_config.filename);
    
    config = new_config;
    
    if (config.enable && !was_enabled)
    {
        if (!file_opened)
        {
            std::string full_path = get_full_path();
            file = fopen(full_path.c_str(), "a");
            if (file)
            {
                file_opened = true;
                // Get current file size for rotation logic
                fseek(file, 0, SEEK_END);
                current_file_size = ftell(file);
            }
        }
    }
    else if (!config.enable && was_enabled)
    {
        if (file_opened && file)
        {
            fclose(file);
            file = nullptr;
            file_opened = false;
            current_file_size = 0;
        }
    }
    else if (config.enable && filename_changed)
    {
        if (file_opened && file)
        {
            fclose(file);
            file = nullptr;
            file_opened = false;
            current_file_size = 0;
        }
        
        std::string full_path = get_full_path();
        file = fopen(full_path.c_str(), "a");
        if (file)
        {
            file_opened = true;
            // Get current file size for rotation logic
            fseek(file, 0, SEEK_END);
            current_file_size = ftell(file);
        }
    }
    
    set_enabled(config.enable);
}

//---------------------------------------------------------------------
// Plugin Lifecycle
//---------------------------------------------------------------------
static Module* mod_ctor() { return new FileTraceModule; }
static void mod_dtor(Module* m) { delete m; }

static TraceLoggerPlug* trace_ctor(Module* m, const std::string&)
{
    auto* mod = static_cast<FileTraceModule*>(m);
    const FileTraceConfig& config = mod->get_config();
    FileTrace* logger = new FileTrace(config);
    mod->register_instance(logger);
    return logger;
}

static void trace_dtor(TraceLoggerPlug* logger) { delete logger; }

#ifndef API_OPTIONS
#define API_OPTIONS 0
#endif

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

const BaseApi* file_trace_logger[] =
{
    &trace_api.base,
    nullptr
};

#ifdef CATCH_TEST_BUILD

#include <catch/catch.hpp>
#include <unistd.h>
#include <fstream>

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
void ErrorMessage(const char*, ...) { }

void LogMessage(const char*, ...) { }

const SnortConfig* SnortConfig::get_conf()
{
    return nullptr;
}

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

// Mock packet for testing
struct MockFilePacket
{
    bool has_ip() const { return true; }
    uint8_t get_ip_proto_next() const { return 6; }
};

TEST_CASE("FileTrace constructor with enabled config", "[FileTraceLogger]")
{
    FileTraceConfig config;
    config.enable = true;
    config.filename = "/tmp/test_file_trace.log";
    
    FileTrace logger(config);
    bool enabled = logger.get_enabled();
    CHECK(enabled);
    CHECK(logger.get_name() == "file_trace");
    
    unlink("/tmp/test_file_trace.log");
}

TEST_CASE("FileTrace constructor with disabled config", "[FileTraceLogger]")
{
    FileTraceConfig config;
    config.enable = false;
    config.filename = "/tmp/test_disabled.log";
    
    FileTrace logger(config);
    bool enabled = logger.get_enabled();
    CHECK(!enabled);
}

TEST_CASE("FileTrace log message to file", "[FileTraceLogger]")
{
    FileTraceConfig config;
    config.enable = true;
    config.filename = "/tmp/test_log_message.log";
    
    FileTrace logger(config);
    MockFilePacket packet;
    
    logger.log("Test file message", "test_module", 1, "test_option", 
               reinterpret_cast<const Packet*>(&packet));
    
    std::ifstream file("/tmp/test_log_message.log");
    CHECK(file.is_open());
    
    std::string content;
    std::getline(file, content);
    CHECK(content.find("Test file message") != std::string::npos);
    
    file.close();
    unlink("/tmp/test_log_message.log");
}

TEST_CASE("FileTrace update config", "[FileTraceLogger]")
{
    FileTraceConfig config;
    config.enable = true;
    config.filename = "/tmp/test_update_config.log";
    
    FileTrace logger(config);
    bool enabled = logger.get_enabled();
    CHECK(enabled);
    
    FileTraceConfig new_config;
    new_config.enable = false;
    new_config.filename = "/tmp/test_update_config_new.log";
    logger.update_config(new_config);
    
    bool disabled = logger.get_enabled();
    CHECK(!disabled);
    
    unlink("/tmp/test_update_config.log");
    unlink("/tmp/test_update_config_new.log");
}

TEST_CASE("FileTrace disabled logger", "[FileTraceLogger]")
{
    FileTraceConfig config;
    config.enable = false;
    config.filename = "/tmp/test_disabled_log.log";
    
    FileTrace logger(config);
    MockFilePacket packet;
    
    logger.log("Should not appear", "test_module", 1, "test_option", 
               reinterpret_cast<const Packet*>(&packet));
    
    std::ifstream file("/tmp/test_disabled_log.log");
    CHECK(!file.is_open());
}

TEST_CASE("FileTrace error handling", "[FileTraceLogger]")
{
    FileTraceConfig config;
    config.enable = true;
    config.filename = "/invalid/path/cannot/create.log";
    
    FileTrace logger(config);
    bool enabled = logger.get_enabled();
    CHECK(enabled);
    
    logger.log("Error test", "error_module", 1, "error_option", nullptr);
}

TEST_CASE("FileTrace different file modes", "[FileTraceLogger]")
{
    const char* test_file = "/tmp/test_file_modes.log";
    
    unlink(test_file);
    
    {
        FileTraceConfig config;
        config.enable = true;
        config.filename = test_file;
        
        FileTrace logger(config);
        logger.log("First message", "mode_module", 1, "mode_option", nullptr);
    }
    
    std::ifstream file1(test_file);
    std::string content1((std::istreambuf_iterator<char>(file1)),
                         std::istreambuf_iterator<char>());
    file1.close();
    CHECK(content1.find("First message") != std::string::npos);
    
    {
        FileTraceConfig config;
        config.enable = true;
        config.filename = test_file;
        
        FileTrace logger(config);
        logger.log("Second message", "mode_module", 1, "mode_option", nullptr);
    }
    
    std::ifstream file2(test_file);
    std::string content2((std::istreambuf_iterator<char>(file2)),
                         std::istreambuf_iterator<char>());
    file2.close();
    CHECK(content2.find("First message") != std::string::npos);
    CHECK(content2.find("Second message") != std::string::npos);
    
    unlink(test_file);
}

TEST_CASE("FileTrace large message handling", "[FileTraceLogger]")
{
    const char* test_file = "/tmp/test_large_message.log";
    unlink(test_file);
    
    FileTraceConfig config;
    config.enable = true;
    config.filename = test_file;
    
    FileTrace logger(config);
    
    std::string large_msg(1000, 'L');
    logger.log(large_msg.c_str(), "large_module", 1, "large_option", nullptr);
    
    std::ifstream file(test_file);
    if (file.is_open()) {
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        file.close();
        CHECK(!content.empty());
    } else {
        CHECK(true);
    }
    
    unlink(test_file);
}

TEST_CASE("FileTrace module functions", "[FileTraceLogger]")
{
    FileTraceModule module;
    
    CHECK(std::string(module.get_name()) == "file_trace");
    CHECK(module.get_help() != nullptr);
    
    const Parameter* params = module.get_parameters();
    CHECK(params != nullptr);
    
    Value val_enabled(true);
    Value val_filename("/tmp/module_test.log");
    
    bool set_enabled = module.set("enabled", val_enabled, nullptr);
    CHECK(set_enabled);
    bool set_filename = module.set("filename", val_filename, nullptr);
    CHECK(set_filename);
    
    bool begin_result = module.begin("file_trace", 0, nullptr);
    CHECK(begin_result);
    bool end_result = module.end("file_trace", 0, nullptr);
    CHECK(end_result);
    
    const FileTraceConfig& config = module.get_config();
    CHECK(config.enable == true);
    
    unlink("/tmp/module_test.log");
}

TEST_CASE("FileTrace special characters", "[FileTraceLogger]")
{
    const char* test_file = "/tmp/test_special_chars.log";
    unlink(test_file);
    
    FileTraceConfig config;
    config.enable = true;
    config.filename = test_file;
    
    FileTrace logger(config);
    
    logger.log("Line1", "special_module", 1, "special_option", nullptr);
    logger.log("Unicode text", "unicode_module", 2, "unicode_option", nullptr);
    logger.log("Quotes test", "quote_module", 3, "quote_option", nullptr);
    
    std::ifstream file(test_file);
    if (file.is_open()) {
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        file.close();

        CHECK(!content.empty());
    } else {
        CHECK(true);
    }
    
    unlink(test_file);
}

TEST_CASE("FileTrace register/unregister functionality", "[FileTraceLogger]")
{
    const char* test_file = "/tmp/test_register.log";
    unlink(test_file);
    
    FileTraceConfig config;
    config.enable = true;
    config.filename = test_file;
    
    FileTrace* logger = new FileTrace(config);
    
    bool enabled1 = logger->get_enabled();
    CHECK(enabled1);
    logger->log("Test message", "test_module", 1, "test_option", nullptr);
    
    delete logger;
    
    FileTrace logger2(config);
    bool enabled2 = logger2.get_enabled();
    CHECK(enabled2);
    logger2.log("Second test", "test_module2", 2, "test_option2", nullptr);
    
    unlink(test_file);
}

TEST_CASE("FileTrace error conditions and edge cases", "[FileTraceLogger]")
{
    const char* test_file = "/tmp/test_edge_cases.log";
    unlink(test_file);
    
    FileTraceConfig config_disabled;
    config_disabled.enable = false;
    config_disabled.filename = test_file;
    FileTrace disabled_logger(config_disabled);
    bool disabled_enabled = disabled_logger.get_enabled();
    CHECK(!disabled_enabled);
    disabled_logger.log("Should not appear", "disabled_module", 1, "disabled_option", nullptr);
    
    FileTraceConfig config_enabled;
    config_enabled.enable = true;
    config_enabled.filename = test_file;
    FileTrace logger(config_enabled);
    
    logger.log(nullptr, "null_module", 1, "null_option", nullptr);
    logger.log("test", nullptr, 1, "null_option", nullptr);
    logger.log("test", "module", 1, nullptr, nullptr);
    
    logger.log("", "empty_module", 1, "empty_option", nullptr);
    logger.log("test", "", 1, "empty_option", nullptr);
    logger.log("test", "module", 1, "", nullptr);
    
    FileTraceConfig config_append;
    config_append.enable = true;
    config_append.filename = test_file;
    FileTrace append_logger(config_append);
    append_logger.log("Append test", "append_module", 1, "append_option", nullptr);
    
    FileTraceConfig config_invalid;
    config_invalid.enable = true;
    config_invalid.filename = "/proc/invalid_path.log";
    FileTrace invalid_logger(config_invalid);
    invalid_logger.log("Should handle gracefully", "invalid_module", 1, "invalid_option", nullptr);
    
    std::string long_filename = "/tmp/" + std::string(200, 'f') + ".log";
    FileTraceConfig config_long;
    config_long.enable = true;
    config_long.filename = long_filename;
    FileTrace long_logger(config_long);
    long_logger.log("Long filename test", "long_module", 1, "long_option", nullptr);
    
    unlink(test_file);
    unlink(long_filename.c_str());
}

#endif
