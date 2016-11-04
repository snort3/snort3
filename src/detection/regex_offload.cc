//--------------------------------------------------------------------------
// Copyright (C) 2016-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "regex_offload.h"

#include <assert.h>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <vector>
#include <thread>

#include "main/snort_config.h"
#include "fp_detect.h"
#include "ips_context.h"

struct RegexRequest
{
    Packet* packet = nullptr;

    std::thread* offload;
    std::mutex mutex;
    std::condition_variable cond;

    unsigned id = 0;
    bool onload = false;
    bool go = true;
};

//--------------------------------------------------------------------------
// foo
//--------------------------------------------------------------------------

RegexOffload::RegexOffload(unsigned max)
{
    for ( unsigned i = 0; i < max; ++i )
    {
        RegexRequest* req = new RegexRequest;
        req->offload = new std::thread(worker, req);
        idle.push_back(req);
    }
}

RegexOffload::~RegexOffload()
{
    assert(busy.empty());

    for ( auto* req : idle )
    {
        req->offload->join();
        delete req->offload;
        delete req;
    }
}

void RegexOffload::stop()
{
    assert(busy.empty());

    for ( auto* req : idle )
    {
        req->go = false;
        std::unique_lock<std::mutex> lock(req->mutex);
        req->cond.notify_one();
    }
}

void RegexOffload::worker(RegexRequest* req)
{
    while ( true )
    {
        std::unique_lock<std::mutex> lock(req->mutex);
        req->cond.wait_for(lock, std::chrono::seconds(1));  // FIXIT-L w/o some hangs upon join

        if ( !req->go )
            break;

        if ( !req->packet )
            continue;

        assert(req->packet->flow->is_offloaded());
        snort_conf = req->packet->context->conf;  // FIXIT-H reload issue
        fp_offload(req->packet);
        req->onload = true;
    }
}

void RegexOffload::put(unsigned id, Packet* p)
{
    assert(!idle.empty());
    RegexRequest* req = idle.front();

    idle.pop_front();  // FIXTHIS-H use splice to move instead
    busy.push_back(req);

    req->id = id;
    req->onload = false;
    req->packet = p;

    std::unique_lock<std::mutex> lock(req->mutex);
    req->cond.notify_one();
}

bool RegexOffload::get(unsigned& id)
{
    assert(!busy.empty());
    RegexRequest* req = busy.front();  // FIXTHIS-H onload any order

    if ( !req->onload )
        return false;

    id = req->id;
    busy.pop_front();  // FIXTHIS-H use splice to move instead
    req->packet = nullptr;
    idle.push_back(req);
    return true;
}

bool RegexOffload::on_hold(Flow* f)
{
    for ( auto* req : busy )
    {
        if ( req->packet->flow == f )
            return true;
    }
    return false;
}

