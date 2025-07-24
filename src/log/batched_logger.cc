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
// batched_logger.cc author Steven Baigal <sbaigal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "batched_logger.h"

#include <algorithm>
#include <cstdlib>
#include <memory>
#include <pthread.h>
#include <sched.h>

#include "control/control_mgmt.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "utils/snort_pcre.h"
#include "utils/util.h"

namespace BatchedLogger
{

thread_local LogBuffer BatchedLogManager::buffer;
BatchQueue BatchedLogManager::queue;
std::thread BatchedLogManager::writer_thread;
std::atomic<bool> BatchedLogManager::running(false);
std::atomic<uint64_t> BatchQueue::overwrite_count(0);

void LogBuffer::append(FILE* fh, bool use_syslog, const char* msg, size_t len)
{
    if (size + len >= LOG_BUFFER_THRESHOLD)
        flush();
    std::memcpy(buffer + size, msg, len);
    size += len;
    this->fh = fh;
    this->use_syslog = use_syslog;
}

void LogBuffer::flush()
{
    if (size == 0)
        return;

    LogBatch batch;
    batch.data.assign(buffer, buffer + size);
    batch.size = size;
    batch.fh = fh;
    batch.use_syslog = use_syslog;
    batch.is_control_message = false;
    BatchedLogManager::push_batch(std::move(batch));
    size = 0;
    last_flush_time = std::chrono::steady_clock::now();
}

void LogBuffer::send_control_message(const char* msg, size_t len)
{
    if (len > LOG_BUFFER_THRESHOLD)
        return;

    LogBatch batch;
    batch.data.assign(msg, msg + len);
    batch.size = len;
    batch.fh = nullptr;
    batch.use_syslog = false;
    batch.is_control_message = true;
    BatchedLogManager::push_batch(std::move(batch));
}

void BatchQueue::push(LogBatch&& batch)
{
    std::lock_guard<std::mutex> lock(mtx);
    size_t next_tail = tail + 1;

    if (next_tail >= LOG_QUEUE_SIZE)
        next_tail = 0;
    if (next_tail == head)
    {
        head++;
        if (head >= LOG_QUEUE_SIZE)
            head = 0;
        overwrite_count++;
    }

    buffer[tail] = std::move(batch);
    tail = next_tail;
    cv.notify_one();
}

bool BatchQueue::pop(LogBatch& batch)
{
    std::unique_lock<std::mutex> lock(mtx);

    if (head == tail)
        return false;

    batch = std::move(buffer[head]);
    head++;
    if (head >= LOG_QUEUE_SIZE)
        head = 0;
    return true;
}

void BatchQueue::wait()
{
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, [this] { return head != tail; });
}

bool BatchQueue::empty() const
{
    std::lock_guard<std::mutex> lock(mtx);
    return head == tail;
}

struct FilterData
{
    std::string filter;
    pcre2_code* re = nullptr;
    pcre2_match_data* match_data = nullptr;
    bool stop_trace = false;
    uint64_t revision = 0;

    void clear()
    {
        if (match_data) pcre2_match_data_free(match_data);
        if (re) pcre2_code_free(re);
        filter.clear();
        match_data = nullptr;
        re = nullptr;
        stop_trace = false;
        revision++;
    }
};


static FilterData s_filter;

static void update_filter(const std::string& pattern_s)
{
    s_filter.clear();
    if (pattern_s.empty())
        return;

    if (pattern_s[0] == 'Y')
        s_filter.stop_trace = true;

    std::string pattern = pattern_s.substr(1);
    int error_code;
    PCRE2_SIZE error_offset;

    pcre2_code* re = pcre2_compile((PCRE2_SPTR)pattern.c_str(), PCRE2_ZERO_TERMINATED,
        PCRE2_MULTILINE, &error_code, &error_offset, nullptr);

    if (!re)
        return;

    pcre2_match_data* match_data = pcre2_match_data_create_from_pattern(re, nullptr);
    if (!match_data)
    {
        pcre2_code_free(re);
        return;
    }

    s_filter.filter = std::move(pattern);
    s_filter.re = re;
    s_filter.match_data = match_data;
}

void BatchedLogManager::set_filter(const std::string& pattern)
{
    LogBuffer::send_control_message(pattern.c_str(), pattern.size());
}

void BatchedLogManager::shutdown()
{
    if (!running)
        return;
    flush_thread_buffers();
    running = false;
    queue.push({});

    if (writer_thread.joinable())
        writer_thread.join();

    if (BatchQueue::get_overwrite_count() > 0)
        fprintf(stderr, "BatchedLogManager Stats: Ring buffer overwrites = %lu\n",
            static_cast<unsigned long>(BatchQueue::get_overwrite_count()));

    if (!s_filter.filter.empty())
        s_filter.clear();
}

void BatchedLogManager::log(FILE* fh, bool use_syslog, const char* msg, size_t len)
{
    buffer.append(fh, use_syslog, msg, len);
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - buffer.last_flush_time);

    if (buffer.size >= LOG_BUFFER_THRESHOLD || elapsed >= LOG_TIME_THRESHOLD)
        buffer.flush();
#ifdef REG_TEST
    flush_thread_buffers(); // Force flush for regression tests
#endif
}

#if 0
void BatchedLogManager::log(FILE* fh, bool use_syslog, const char* format, va_list& ap)
{
    static char temp[1024];
    int len = vsnprintf(temp, sizeof(temp), format, ap);

    buffer.append(fh, use_syslog, temp, len);
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - buffer.last_flush_time);

    if (buffer.size >= LOG_BUFFER_THRESHOLD || elapsed >= LOG_TIME_THRESHOLD)
        buffer.flush();

#ifdef REG_TEST
    flush_thread_buffers(); // Force flush for regression tests
#endif

}
#endif
void BatchedLogManager::flush_thread_buffers()
{
    buffer.flush();
}

void BatchedLogManager::push_batch(LogBatch&& batch)
{
    queue.push(std::move(batch));
}

void BatchedLogManager::print_batch(const LogBatch& batch)
{
    static bool stop_trace = false;
    static uint64_t revision = 0;

    // reset condition if filter was changed by user
    if (s_filter.revision != revision)
    {
        revision = s_filter.revision;
        stop_trace = false;
    }
    if (stop_trace)
        return;

    if (!s_filter.filter.empty())
    {
        int rc = pcre2_match(
            s_filter.re, reinterpret_cast<PCRE2_SPTR>(batch.data.data()),
            batch.size, 0, 0, s_filter.match_data, nullptr);

        if (rc < 0)
            return; // Skip printing if no match
        stop_trace = s_filter.stop_trace;
        revision = s_filter.revision;
    }

    if (!batch.use_syslog && batch.fh)
    {
        if ( snort::SnortConfig::log_quiet() and batch.fh == stdout )
            return;

        fprintf(batch.fh, "%.*s", static_cast<int>(batch.size), batch.data.data());
        fflush(batch.fh);
    }
    else
    {
        const char* data = batch.data.data();
        size_t len = batch.size;
        const char* start = data;
        const char* end = data + len;

        while (start < end)
        {
            const char* line_end = start;

            while (line_end < end && *line_end != '\n')
                ++line_end;

            size_t line_len = line_end - start;

            if (line_len > 0)
                syslog(LOG_DAEMON | LOG_NOTICE, "%.*s", static_cast<int>(line_len), start);

            start = line_end + 1;
        }
    }
#ifdef SHELL
    if (stop_trace)
        if (!ControlMgmt::send_command_to_socket("packet_tracer.disable()\n"))
            fprintf(stderr, "Batched_logger: Failed to send command to control socket\n");
#endif
}

void BatchedLogManager::writer_thread_func()
{
    while (running || !queue.empty())
    {
        LogBatch batch;

        if (queue.pop(batch))
        {
            if (batch.is_control_message)
                update_filter(std::string(batch.data.data(), batch.size));
            else
                print_batch(batch);
        }
        else
            queue.wait();
    }
}

void BatchedLogManager::init()
{
    running = true;

    snort::ThreadConfig* thread_config = snort::SnortConfig::get_conf()->thread_config;
    thread_config->implement_named_thread_affinity("BatchedLoggerWriter");
    writer_thread = std::thread(writer_thread_func);
    SET_THREAD_NAME(writer_thread.native_handle(), "snort.logger");
    thread_config->implement_thread_affinity(STHREAD_TYPE_MAIN, snort::ThreadConfig::DEFAULT_THREAD_ID);

    std::atexit(BatchedLogManager::shutdown);

    sched_param sch_params;
    sch_params.sched_priority = 1;
    pthread_setschedparam(writer_thread.native_handle(), SCHED_OTHER, &sch_params);
}

} // namespace BatchedLogger
