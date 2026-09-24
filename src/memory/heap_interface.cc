//--------------------------------------------------------------------------
// Copyright (C) 2023-2026 Cisco and/or its affiliates. All rights reserved.
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

// heap_interface.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "heap_interface.h"

#include <cassert>
#include <cstring>

#if defined(HAVE_JEMALLOC) && !defined(UNIT_TEST_BUILD)
#include <jemalloc/jemalloc.h>
#ifdef HAVE_CISCO_SHIM
#include "shim.h"
#endif
#endif

#include "control/control.h"
#include "log/messages.h"

namespace memory
{

// -----------------------------------------------------------------------------
#if defined(HAVE_JEMALLOC) && !defined(UNIT_TEST_BUILD)
class JemallocInterface : public HeapInterface
{
public:
    JemallocInterface()
    {
#ifdef HAVE_CISCO_SHIM
        char shim_cfg[1024];
        snort::LogMessage("%s", shim_print_config(shim_cfg, sizeof(shim_cfg)));
#endif
    }

    ~JemallocInterface() override { }

    void main_init() override;
    void thread_init() override;

    void get_process_total(uint64_t&, uint64_t&, bool bump_epoch) override;
    void get_thread_allocs(uint64_t&, uint64_t&) override;

    void print_stats(ControlConn*) override;

    void get_aux_counts(uint64_t&, uint64_t&, uint64_t&, uint64_t&) override;

    void profile_config(bool enable, uint64_t sample_rate) override;
    void dump_profile(ControlConn*) override;
    void show_profile_config(ControlConn*) override;
    void get_debug_stats(uint64_t&, uint64_t&, uint64_t&, uint64_t&) override;
};

static size_t stats_mib[2], mib_len = 2;

static const uint64_t alloc_zero = 0;
static const uint64_t dealloc_zero = 0;
static THREAD_LOCAL const uint64_t* alloc_ptr = &alloc_zero;
static THREAD_LOCAL const uint64_t* dealloc_ptr = &dealloc_zero;

static ControlConn* s_ctrlconn = nullptr;
static void log_jem_stats(void *,const char *buf)
{
    if (s_ctrlconn)
    {
        char tmp[STD_BUF];
        const char* end = buf + strlen(buf);
        for(const char* p = buf; p < end ;)
        {
            int n = (end - p > (STD_BUF - 1)) ? (STD_BUF - 1) : (end - p);
            std::memcpy(tmp, p, n);
            tmp[n] = '\0';
            s_ctrlconn->respond("%s", tmp);
            p += n;
        }
    }
}

void JemallocInterface::main_init()
{
    mallctlnametomib("stats.mapped", stats_mib, &mib_len);
}

void JemallocInterface::thread_init()
{
    size_t sz = sizeof(alloc_ptr);

    // __STRDUMP_DISABLE__
    mallctl("thread.allocatedp", (void*)&alloc_ptr, &sz, nullptr, 0);
    mallctl("thread.deallocatedp", (void*)&dealloc_ptr, &sz, nullptr, 0);
    // __STRDUMP_ENABLE__
}

void JemallocInterface::get_process_total(uint64_t& epoch, uint64_t& utotal, bool bump_epoch)
{
    uint64_t cycle = 13;
    size_t sz = sizeof(epoch);

    if (!bump_epoch)
    {
        // Don't bump the epoch -- use cached stats values
        epoch = 0;
    }
    else
    {
        mallctl("epoch", (void*)&epoch, &sz, (void*)&cycle, sizeof(cycle));
    }

    size_t total;
    sz = sizeof(total);
    mallctlbymib(stats_mib, mib_len, (void*)&total, &sz, NULL, 0);

    utotal = total;
}

void JemallocInterface::get_thread_allocs(uint64_t& alloc, uint64_t& dealloc)
{
    assert(alloc_ptr);
    assert(dealloc_ptr);

    alloc = *alloc_ptr;
    dealloc = *dealloc_ptr;
}

void JemallocInterface::print_stats(ControlConn* ctrlcon)
{
    s_ctrlconn = ctrlcon;
    malloc_stats_print(log_jem_stats, nullptr, nullptr);
}

void JemallocInterface::get_aux_counts(uint64_t& all, uint64_t& act, uint64_t& res, uint64_t& ret)
{
    size_t sz = sizeof(all);

    mallctl("stats.allocated", (void*)&all, &sz, nullptr, 0);
    mallctl("stats.active", (void*)&act, &sz, nullptr, 0);
    mallctl("stats.resident", (void*)&res, &sz, nullptr, 0);
    mallctl("stats.retained", (void*)&ret, &sz, nullptr, 0);
}

void JemallocInterface::profile_config(bool enable, uint64_t sample_rate)
{
    bool en = enable;
    int ret = mallctl("prof.active", nullptr, nullptr, &en, sizeof(bool));
    if ( ret )
        snort::LogMessage("Error in setting jemalloc profile config : %d", ret);
    
    if ( enable )
    {
        size_t sample = sample_rate;
        ret = mallctl("prof.reset", nullptr, nullptr, &sample, sizeof(size_t));
        if ( ret )
            snort::LogMessage("Error in setting jemalloc sample rate : %d", ret);
    }
}

void JemallocInterface::dump_profile(ControlConn* ctrlcon)
{
    int ret = mallctl("prof.dump", nullptr, nullptr, nullptr, 0);
    if ( ret )
        snort::LogMessage("Error in dumping jemalloc profile : %d", ret);
    else
        ctrlcon->respond("Jemalloc memory profile dumped\n");
}

void JemallocInterface::show_profile_config(ControlConn* ctrlcon)
{
    bool enable = false;
    size_t sz = sizeof(enable);
    int ret = mallctl("prof.active", &enable, &sz, nullptr, 0);
    if ( ret )
        snort::LogMessage("Error in getting jemalloc profiling config : %d", ret);

    if ( enable )
    {
        size_t sample = 0;
        sz = sizeof(sample);
        ret = mallctl("prof.lg_sample", &sample, &sz, nullptr, 0);
        if ( ret )
            snort::LogMessage("Error in getting jemalloc sample rate : %d", ret);

        ctrlcon->respond("Jemalloc memory profiling is enabled with sample rate %lu\n", sample);
    }
    else
    {
        ctrlcon->respond("Jemalloc memory profiling is disabled\n");
    }
}

void JemallocInterface::get_debug_stats(uint64_t& fnadd, uint64_t& freen,
    uint64_t& foverwrite, uint64_t& fbuffered)
{
#ifdef HAVE_CISCO_SHIM
    shim_stats_t stats;
    shim_get_stats(&stats);
    fnadd = stats.dpf_n_added;
    freen = stats.dpf_n_freed;
    foverwrite = stats.dpf_n_overwrites;
    fbuffered = stats.dpf_n_bytes_buffered;
#else
    fnadd = freen = foverwrite = fbuffered = 0;
#endif
}

//--------------------------------------------------------------------------
#else  // disabled interface
//--------------------------------------------------------------------------

class NerfedInterface : public HeapInterface
{
public:
    void main_init() override { }
    void thread_init() override { }

    void get_process_total(uint64_t& e, uint64_t& t, bool bump_epoch) override
    { e = t = 0; UNUSED(bump_epoch); }

    void get_thread_allocs(uint64_t& a, uint64_t& d) override
    { a = d = 0; }
};

#endif

HeapInterface* HeapInterface::get_instance()
{
#if defined(HAVE_JEMALLOC) && !defined(UNIT_TEST_BUILD)
    return new JemallocInterface;
#else
    return new NerfedInterface;
#endif
}

}  // memory
