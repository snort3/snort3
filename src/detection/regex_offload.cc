//--------------------------------------------------------------------------
// Copyright (C) 2016-2019 Cisco and/or its affiliates. All rights reserved.
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

// FIXIT-L this could be offloader specific
struct RegexRequest
{
    snort::Packet* packet = nullptr;

    std::thread* thread;
    std::mutex mutex;
    std::condition_variable cond;

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

    for ( auto* req : idle )
        delete req;
}

void RegexOffload::stop()
{
    assert(busy.empty());
}

bool RegexOffload::on_hold(snort::Flow* f) const
{
    for ( auto* req : busy )
    {
        if ( req->packet->flow == f )
            return true;
    }
    return false;
}

//--------------------------------------------------------------------------
// synchronous (ie non) offload implementation
//--------------------------------------------------------------------------

MpseRegexOffload::MpseRegexOffload(unsigned max) : RegexOffload(max) { }

void MpseRegexOffload::put(snort::Packet* p)
{
    assert(p);
    assert(!idle.empty());

    RegexRequest* req = idle.front();
    idle.pop_front();  // FIXIT-H use splice to move instead
    busy.emplace_back(req);

    req->packet = p;

    if (p->context->searches.items.size() > 0)
        p->context->searches.offload_search();
}

bool MpseRegexOffload::get(snort::Packet*& p)
{
    assert(!busy.empty());

    for ( auto i = busy.begin(); i != busy.end(); i++ )
    {
        RegexRequest* req = *i;
        snort::IpsContext* c = req->packet->context;

        if ( c->searches.items.size() > 0 )
        {
            snort::Mpse::MpseRespType resp_ret = c->searches.receive_offload_responses();

            if (resp_ret == snort::Mpse::MPSE_RESP_NOT_COMPLETE)
                continue;

            else if (resp_ret == snort::Mpse::MPSE_RESP_COMPLETE_FAIL)
            {
                if (!c->searches.can_fallback())
                {
                    // FIXIT-M Add peg counts to record offload search fallback attempts
                    c->searches.search_sync();
                }
                // FIXIT-M else Add peg counts to record offload search failures
            }
            c->searches.items.clear();
        }

        p = req->packet;
        req->packet = nullptr;

        busy.erase(i);
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
    for ( auto* req : idle )
        req->thread = new std::thread(worker, req, snort::SnortConfig::get_conf());
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

void ThreadRegexOffload::put(snort::Packet* p)
{
    assert(p);
    assert(!idle.empty());

    RegexRequest* req = idle.front();
    idle.pop_front();  // FIXIT-H use splice to move instead
    busy.emplace_back(req);

    std::unique_lock<std::mutex> lock(req->mutex);
    req->packet = p;

    if (p->context->searches.items.size() > 0)
    {
        req->offload = true;
        req->cond.notify_one();
    }
}

bool ThreadRegexOffload::get(snort::Packet*& p)
{
    assert(!busy.empty());

    for ( auto i = busy.begin(); i != busy.end(); i++ )
    {
        RegexRequest* req = *i;

        if ( req->offload )
            continue;

        p = req->packet;
        req->packet = nullptr;

        busy.erase(i);
        idle.emplace_back(req);

        return true;
    }

    p = nullptr;
    return false;
}

void ThreadRegexOffload::worker(RegexRequest* req, snort::SnortConfig* initial_config)
{
    snort::SnortConfig::set_conf(initial_config);

    while ( true )
    {
        {
            std::unique_lock<std::mutex> lock(req->mutex);
            req->cond.wait_for(lock, std::chrono::seconds(1));

            // setting conf is somewhat expensive, checking the conf is not
            // this occurs here to take advantage if idling
            if ( req->packet and req->packet->context->conf != snort::SnortConfig::get_conf() )
                snort::SnortConfig::set_conf(req->packet->context->conf);

            if ( !req->go )
                break;

            if ( !req->offload )
                continue;
        }

        assert(req->packet);
        assert(req->packet->is_offloaded());
        assert(req->packet->context->searches.items.size() > 0);

        snort::MpseBatch& batch = req->packet->context->searches;
        batch.offload_search();
        snort::Mpse::MpseRespType resp_ret;

        do
        {
            resp_ret = batch.receive_offload_responses();
        }
        while (resp_ret == snort::Mpse::MPSE_RESP_NOT_COMPLETE);

        if (resp_ret == snort::Mpse::MPSE_RESP_COMPLETE_FAIL)
        {
            if (!batch.can_fallback())
            {
                // FIXIT-M Add peg counts to record offload search fallback attempts
                batch.search_sync();
            }
            // FIXIT-M else Add peg counts to record offload search failures
        }

        batch.items.clear();
        req->offload = false;
    }

    // FIXIT-M break this over-coupling. In reality we shouldn't be evaluating latency in offload.
    PacketLatency::tterm();
    RuleLatency::tterm();
}

