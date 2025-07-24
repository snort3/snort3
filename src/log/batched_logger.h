//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// batched_logger.h author Steven Baigal <sbaigal@cisco.com>

#ifndef BATCHED_LOGGER_H
#define BATCHED_LOGGER_H

#include <atomic>
#include <condition_variable>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <syslog.h>
#include <stdio.h>
#include <vector>
#include <thread>

namespace BatchedLogger
{

const size_t LOG_BUFFER_THRESHOLD = 8192;
const size_t LOG_QUEUE_SIZE = 8192;
const std::chrono::milliseconds LOG_TIME_THRESHOLD(10);

struct LogBatch
{
    std::vector<char> data;
    size_t size = 0;
    FILE* fh = nullptr;
    bool use_syslog = false;
    bool is_control_message = false;
};

class LogBuffer
{
public:
    char buffer[LOG_BUFFER_THRESHOLD];
    size_t size = 0;
    std::chrono::steady_clock::time_point last_flush_time = std::chrono::steady_clock::now();

    void append(FILE* fh, bool use_syslog, const char* msg, size_t len);
    void flush();
    static void send_control_message(const char* msg, size_t len);
private:
    FILE* fh = nullptr;
    bool use_syslog = true;
};

class BatchQueue
{
private:
    std::vector<LogBatch> buffer;
    size_t head = 0;
    size_t tail = 0;
    mutable std::mutex mtx;
    std::condition_variable cv;
    static std::atomic<uint64_t> overwrite_count;

public:
    BatchQueue() : buffer(LOG_QUEUE_SIZE) {}

    void push(LogBatch&& batch);
    bool pop(LogBatch& batch);
    void wait();
    bool empty() const;
    static uint64_t get_overwrite_count() { return overwrite_count.load(); }
};

class BatchedLogManager
{
public:
    static void init();
    static void shutdown();
    static void log(FILE* fh, bool use_syslog, const char* msg, size_t len);
    //static void log(FILE* fh, bool use_syslog, const char* format, va_list& ap);
    static void flush_thread_buffers();
    static void push_batch(LogBatch&& batch);
    static void set_filter(const std::string& filter);

private:
    static thread_local LogBuffer buffer;
    static BatchQueue queue;
    static std::thread writer_thread;
    static std::atomic<bool> running;

    static void writer_thread_func();
    static void print_batch(const LogBatch& batch);
};

} // namespace BatchedLogger

#endif // BATCHED_LOGGER_H
