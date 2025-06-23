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

// std_connector_buffer.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "std_connector_buffer.h"

#include <algorithm>
#include <vector>

#include "log/text_log.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "utils/util.h"

using namespace snort;
using namespace std;

#define FLUSHER_THREAD_NAME "std_connector.flusher"

static void flusher(const SnortConfig* initial_config, const char* output,
    mutex& rings_mutex, list<Ring2>& rings, atomic_flag& latest, atomic_flag& run)
{
    ThreadConfig *thread_config = initial_config->thread_config;
    thread_config->implement_named_thread_affinity(FLUSHER_THREAD_NAME);
    SET_THREAD_NAME(pthread_self(), FLUSHER_THREAD_NAME);

    SnortConfig local_config;
    local_config.merge(initial_config);
    SnortConfig::set_conf(&local_config);

    TextLog* out = TextLog_Init(output, false);
    list<Ring2::Reader> readers;

    latest.clear();

    while (run.test_and_set())
    {
        if (!rings_mutex.try_lock())
            continue;

        if (!latest.test_and_set())
        {
            readers.clear();
            for (auto& ring : rings)
                readers.emplace_back(ring.reader());
        }

        for (auto& reader : readers)
        {
            reader.retry();

            size_t data_len = 0;
            void* data = nullptr;

            while ((data = reader.read(data_len)) and data_len > 0)
                TextLog_Print(out, "%.*s\n", (int)data_len, (char*)data);

            reader.pop();
        }

        rings_mutex.unlock();

        TextLog_Flush(out);

        this_thread::yield();
    }

    {
        lock_guard<mutex> lock(rings_mutex);

        if (!latest.test_and_set())
        {
            readers.clear();
            for (auto& ring : rings)
                readers.emplace_back(ring.reader());
        }

        for (auto& reader : readers)
        {
            reader.retry();

            size_t data_len = 0;
            void* data = nullptr;

            while ((data = reader.read(data_len)) and data_len > 0)
                TextLog_Print(out, "%.*s\n", (int)data_len, (char*)data);

            reader.pop();
        }
    }

    TextLog_Flush(out);
    TextLog_Term(out);
    SnortConfig::set_conf(nullptr);
}

StdConnectorBuffer::StdConnectorBuffer(const char* output)
{
    if (!output)
        return;

    destination = output;
}

StdConnectorBuffer::~StdConnectorBuffer()
{
    sink_run.clear();

    if (sink)
        sink->join();

    delete sink;
}

void StdConnectorBuffer::start()
{
    scoped_lock<mutex, mutex> lock(start_mutex, rings_mutex);

    if (sink)
        return;

    if (destination.empty())
        return;

    auto sc = SnortConfig::get_conf();

    if (!sc)
        return;

    sink_latest.test_and_set();
    sink_run.test_and_set();
    // coverity[missing_lock]
    sink = new thread(flusher, sc, destination.c_str(), ref(rings_mutex), ref(rings), ref(sink_latest), ref(sink_run));

    while (sink_latest.test_and_set());
}

Ring2::Writer StdConnectorBuffer::acquire(size_t buffer_size)
{
    lock_guard<mutex> lock(rings_mutex);

    rings.emplace_back(buffer_size);

    sink_latest.clear();

    return rings.back().writer();
}

bool StdConnectorBuffer::release(const Ring2::Writer& writer)
{
    lock_guard<mutex> lock(rings_mutex);

    // check for removed rings if they can be deleted
    bool updated = false;
    auto ring_removed = rings_removed.begin();

    while (ring_removed != rings_removed.end())
    {
        if ((*ring_removed)->empty())
        {
            auto ring = *ring_removed;
            rings.erase(ring);
            ring_removed = rings_removed.erase(ring_removed);
            updated = true;
        }
        else
            ring_removed++;
    }

    if (updated)
        sink_latest.clear();

    // mark the ring for deletion
    auto ring = find_if(rings.begin(), rings.end(),
        [&](const Ring2& r) { return r.native(writer); });

    if (ring == rings.end())
        return false;

    rings_removed.push_back(ring);

    return true;
}
