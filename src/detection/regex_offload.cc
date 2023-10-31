//--------------------------------------------------------------------------
// Copyright (C) 2016-2023 Cisco and/or its affiliates. All rights reserved.
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

// regex_offload.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "regex_offload.h"

#include <cassert>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <vector>
#include <thread>

#include "fp_detect.h"
#include "ips_context.h"
#include "latency/packet_latency.h"
#include "latency/rule_latency.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "main/thread_config.h"
#include "managers/module_manager.h"
#include "utils/stats.h"

using namespace snort;

// FIXIT-L this could be offloader specific
struct RegexRequest
{
    Packet* packet = nullptr;

    std::thread* thread;
    std::mutex mutex;
    std::condition_variable cond;

#ifdef REG_TEST
    // used to make main thread wait for results to get predictable behavior
    std::mutex sync_mutex;
    std::condition_variable sync_cond;
#endif

    std::atomic<bool> offload { false };

    bool go = true;
};

RegexOffload* RegexOffload::get_offloader(unsigned max, bool async)
{
    if ( async )
        return new ThreadRegexOffload(max);

    return new MpseRegexOffload(max);
}

//--------------------------------------------------------------------------
// base offload implementation
//--------------------------------------------------------------------------

RegexOffload::RegexOffload(unsigned max)
{
    for ( unsigned i = 0; i < max; ++i )
    {
        RegexRequest* req = new RegexRequest;
        idle.emplace_back(req);
    }
}

RegexOffload::~RegexOffload()
{
    assert(busy.empty());

    for ( const auto* req : idle )
        delete req;
}

void RegexOffload::stop()
{
    assert(busy.empty());
}

bool RegexOffload::on_hold(const Flow* f) const
{
    return std::any_of(busy.cbegin(), busy.cend(), [f](const RegexRequest* req){ return req->packet->flow == f; });
}

//--------------------------------------------------------------------------
// synchronous (ie non) offload implementation
//--------------------------------------------------------------------------

MpseRegexOffload::MpseRegexOffload(unsigned max) : RegexOffload(max) { }

void MpseRegexOffload::put(Packet* p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(mpsePerfStats);

    assert(p);
    assert(!idle.empty());
    assert(p->context->searches.items.size() > 0);

    RegexRequest* req = idle.front();
    idle.pop_front();

    busy.emplace_back(req);
    // Because a list is a doubly linked list we can store the iterator
    // for later quick removal of this item from the list
    p->context->regex_req_it = std::prev(busy.end());

    req->packet = p;
    p->context->searches.offload_search();
}

bool MpseRegexOffload::get(Packet*& p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(mpsePerfStats);
    assert(!busy.empty());

    Mpse::MpseRespType resp_ret;
    MpseBatch* batch;

    resp_ret = MpseBatch::poll_offload_responses(batch);

    if (resp_ret != Mpse::MPSE_RESP_NOT_COMPLETE)
    {
        if (resp_ret == Mpse::MPSE_RESP_COMPLETE_FAIL)
        {
            if (batch->can_fallback())
            {
                batch->search_sync();
                pc.offload_fallback++;
            }
            pc.offload_failures++;
        }

        IpsContext* c = (IpsContext*)(batch->context);
        p = c->packet;

        // Finished with items in batch so clear
        batch->items.clear();

        RegexRequest* req = *(c->regex_req_it);
        req->packet = nullptr;
        busy.erase(c->regex_req_it);
        idle.emplace_back(req);

        return true;
    }

    p = nullptr;
    return false;
}

//--------------------------------------------------------------------------
// async (threads) offload implementation
//--------------------------------------------------------------------------

ThreadRegexOffload::ThreadRegexOffload(unsigned max) : RegexOffload(max)
{
    unsigned i = ThreadConfig::get_instance_max();
    const SnortConfig* sc = SnortConfig::get_conf();

    for ( auto* req : idle )
        req->thread = new std::thread(worker, req, sc, i++);
}

ThreadRegexOffload::~ThreadRegexOffload()
{
    for ( auto* req : idle )
    {
        req->thread->join();
        delete req->thread;
    }
}

void ThreadRegexOffload::stop()
{
    RegexOffload::stop();

    for ( auto* req : idle )
    {
        std::unique_lock<std::mutex> lock(req->mutex);
        req->go = false;
        req->cond.notify_one();
    }
}

void ThreadRegexOffload::put(Packet* p)
{
    // cppcheck-suppress unreadVariable
    Profile profile(mpsePerfStats);

    assert(p);
    assert(!idle.empty());
    assert(p->context->searches.items.size() > 0);

    RegexRequest* req = idle.front();
    idle.pop_front();

    busy.emplace_back(req);
    p->context->regex_req_it = std::prev(busy.end());

    {
        std::unique_lock<std::mutex> lock(req->mutex);
        req->packet = p;

        req->offload = true;
        req->cond.notify_one();
    }

#ifdef REG_TEST
    {
        std::unique_lock<std::mutex> sync_lock(req->sync_mutex);
        while ( req->offload and req->sync_cond.wait_for(sync_lock, std::chrono::seconds(1))
            == std::cv_status::timeout );
    }
#endif
}

bool ThreadRegexOffload::get(Packet*& p)
{
    Profile profile(mpsePerfStats);
    assert(!busy.empty());

    for ( auto i = busy.begin(); i != busy.end(); i++ )
    {
        RegexRequest* req = *i;

        if ( req->offload )
            continue;

        p = req->packet;
        assert(p->context->regex_req_it == i);
        req->packet = nullptr;

        busy.erase(i);
        idle.emplace_back(req);

        return true;
    }

    p = nullptr;
    return false;
}

void ThreadRegexOffload::worker(
    RegexRequest* req, const SnortConfig* initial_config, unsigned id)
{
    set_instance_id(id);
    SnortConfig::set_conf(initial_config);

    while ( true )
    {
        {
            std::unique_lock<std::mutex> lock(req->mutex);
            req->cond.wait_for(lock, std::chrono::seconds(1));

            if ( !req->go )
                break;

            if ( !req->offload )
                continue;
        }

        assert(req->packet);
        assert(req->packet->is_offloaded());
        assert(req->packet->context->searches.items.size() > 0);

        SnortConfig::set_conf(req->packet->context->conf);
        IpsContext* c = req->packet->context;
        Mpse::MpseRespType resp_ret;

        c->searches.offload_search();

        do
        {
            resp_ret = c->searches.receive_offload_responses();
        }
        while (resp_ret == Mpse::MPSE_RESP_NOT_COMPLETE);

        if (resp_ret == Mpse::MPSE_RESP_COMPLETE_FAIL)
        {
            if (c->searches.can_fallback())
            {
                c->searches.search_sync();
                pc.offload_fallback++;
            }
            pc.offload_failures++;
        }

        c->searches.items.clear();
        req->offload = false;

#ifdef REG_TEST
        {
            std::unique_lock<std::mutex> lock(req->sync_mutex);
            req->sync_cond.notify_one();
        }
#endif
    }
    ModuleManager::accumulate_module("search_engine");
    ModuleManager::accumulate_module("detection");

    // FIXIT-M break this over-coupling. In reality we shouldn't be evaluating latency in offload.
    PacketLatency::tterm();
    RuleLatency::tterm();
}

