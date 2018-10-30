//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_config.h"
#include "latency/packet_latency.h"
#include "latency/rule_latency.h"
#include "fp_detect.h"
#include "ips_context.h"

struct RegexRequest
{
    snort::Packet* packet = nullptr;

    std::thread* thread;
    std::mutex mutex;
    std::condition_variable cond;

    std::atomic<bool> offload { false };

    unsigned id = 0;
    bool go = true;
};

//--------------------------------------------------------------------------
// regex offload implementation
//--------------------------------------------------------------------------

RegexOffload::RegexOffload(unsigned max)
{
    for ( unsigned i = 0; i < max; ++i )
    {
        RegexRequest* req = new RegexRequest;
        req->thread = new std::thread(worker, req);
        idle.emplace_back(req);
    }
}

RegexOffload::~RegexOffload()
{
    assert(busy.empty());

    for ( auto* req : idle )
    {
        req->thread->join();
        delete req->thread;
        delete req;
    }
}

void RegexOffload::stop()
{
    assert(busy.empty());

    for ( auto* req : idle )
    {
        std::unique_lock<std::mutex> lock(req->mutex);
        req->go = false;
        req->cond.notify_one();
    }
}

void RegexOffload::worker(RegexRequest* req)
{
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
        assert(req->packet->flow->is_offloaded());

        snort::SnortConfig::set_conf(req->packet->context->conf);  // FIXIT-H reload issue
        fp_offload(req->packet);

        req->offload = false;
    }
    tterm();
}

void RegexOffload::tterm()
{
    // FIXIT-M break this over-coupling. In reality we shouldn't be evaluating latency in offload.
    PacketLatency::tterm();
    RuleLatency::tterm();
}

void RegexOffload::put(unsigned id, snort::Packet* p)
{
    assert(p);
    assert(!idle.empty());

    RegexRequest* req = idle.front();

    idle.pop_front();  // FIXIT-H use splice to move instead
    busy.emplace_back(req);

    std::unique_lock<std::mutex> lock(req->mutex);

    req->id = id;
    req->packet = p;
    req->offload = true;

    req->cond.notify_one();
}

bool RegexOffload::get(unsigned& id)
{
    assert(!busy.empty());

    // FIXIT-H onload flows in any order
    RegexRequest* req = busy.front();

    if ( req->offload )
        return false;

    id = req->id;
    req->packet = nullptr;

    busy.pop_front();  // FIXIT-H use splice to move instead
    idle.emplace_back(req);

    return true;
}

bool RegexOffload::on_hold(snort::Flow* f)
{
    for ( auto* req : busy )
    {
        if ( req->packet->flow == f )
            return true;
    }
    return false;
}

