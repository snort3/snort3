//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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
// flow_cache.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/flow_cache.h"

#include "flow/ha.h"
#include "hash/zhash.h"
#include "helpers/flag_context.h"
#include "ips_options/ips_flowbits.h"
#include "packet_io/active.h"
#include "time/packet_time.h"
#include "utils/stats.h"

#include "flow_key.h"

using namespace snort;

#define SESSION_CACHE_FLAG_PURGING  0x01

//-------------------------------------------------------------------------
// FlowCache stuff
//-------------------------------------------------------------------------

FlowCache::FlowCache (const FlowConfig& cfg) : config(cfg)
{
    hash_table = new ZHash(config.max_sessions, sizeof(FlowKey));
    hash_table->set_keyops(FlowKey::hash, FlowKey::compare);

    uni_head = new Flow;
    uni_tail = new Flow;

    uni_head->next = uni_tail;
    uni_tail->prev = uni_head;

    uni_count = 0;
    flags = 0x0;

    assert(prune_stats.get_total() == 0);
}

FlowCache::~FlowCache ()
{
    while ( Flow* flow = (Flow*)hash_table->pop() )
        flow->term();

    delete uni_head;
    delete uni_tail;

    delete hash_table;
}

void FlowCache::push(Flow* flow)
{
    void* key = hash_table->push(flow);
    flow->key = (FlowKey*)key;
}

unsigned FlowCache::get_count()
{
    return hash_table ? hash_table->get_count() : 0;
}

Flow* FlowCache::find(const FlowKey* key)
{
    Flow* flow = (Flow*)hash_table->find(key);

    if ( flow )
    {
        time_t t = packet_time();

        if ( flow->last_data_seen < t )
            flow->last_data_seen = t;
    }

    return flow;
}

// always prepend
void FlowCache::link_uni(Flow* flow)
{
    flow->next = uni_head->next;
    flow->prev = uni_head;

    uni_head->next->prev = flow;
    uni_head->next = flow;

    ++uni_count;
}

// but remove from any point
void FlowCache::unlink_uni(Flow* flow)
{
    if ( !flow->next )
        return;

    --uni_count;

    flow->next->prev = flow->prev;
    flow->prev->next = flow->next;

    flow->next = flow->prev = nullptr;
}

Flow* FlowCache::get(const FlowKey* key)
{
    time_t timestamp = packet_time();
    Flow* flow = (Flow*)hash_table->get(key);

    if ( !flow )
    {
        if ( !prune_stale(timestamp, nullptr) )
        {
            if ( !prune_unis() )
                prune_excess(nullptr);
        }

        flow = (Flow*)hash_table->get(key);

        assert(flow);
        flow->reset();
        link_uni(flow);
    }

    flow->last_data_seen = timestamp;

    return flow;
}

int FlowCache::release(Flow* flow, PruneReason reason, bool do_cleanup)
{
    flow->reset(do_cleanup);
    prune_stats.update(reason);
    return remove(flow);
}

int FlowCache::remove(Flow* flow)
{
    if ( flow->next )
        unlink_uni(flow);

    return hash_table->remove(flow->key);
}

unsigned FlowCache::prune_stale(uint32_t thetime, const Flow* save_me)
{
    ActiveSuspendContext act_susp;

    unsigned pruned = 0;
    auto flow = static_cast<Flow*>(hash_table->first());

    while ( flow and pruned <= cleanup_flows )
    {
#if 0
        // FIXIT-H this loops forever if 1 flow in cache
        if (flow == save_me)
        {
            break;
            if ( hash_table->get_count() == 1 )
                break;

            hash_table->touch();
        }
#else
        // Reached the current flow. This *should* be the newest flow
        if ( flow == save_me )
        {
            // assert( flow->last_data_seen + config.pruning_timeout >= thetime );
            // bool rv = hash_table->touch(); assert( !rv );
            break;
        }
#endif
        if ( flow->is_offloaded() )
            break;

        if ( flow->last_data_seen + config.pruning_timeout >= thetime )
            break;

        flow->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
        release(flow, PruneReason::IDLE);
        ++pruned;

        flow = static_cast<Flow*>(hash_table->first());
    }

    return pruned;
}

unsigned FlowCache::prune_unis()
{
    ActiveSuspendContext act_susp;

    // we may have many or few unis; need to find reasonable ratio
    // FIXIT-M max_uni should be based on typical ratios seen in perfmon
    const unsigned max_uni = (config.max_sessions >> 2) + 1;

    Flow* curr = uni_tail->prev;
    unsigned pruned = 0;

    while ( (uni_count > max_uni) && curr && (pruned < cleanup_flows) )
    {
        Flow* flow = curr;
        curr = curr->prev;

        if ( flow->was_blocked() )
            continue;

        release(flow, PruneReason::UNI);
        ++pruned;
    }

    return pruned;
}

unsigned FlowCache::prune_excess(const Flow* save_me)
{
    ActiveSuspendContext act_susp;

    auto max_cap = config.max_sessions - cleanup_flows;
    assert(max_cap > 0);

    unsigned pruned = 0;
    unsigned blocks = 0;

    // initially skip offloads but if that doesn't work the hashtable is iterated from the
    // beginning again. prune offloads at that point.
    unsigned ignore_offloads = hash_table->get_count();

    while ( hash_table->get_count() > max_cap and hash_table->get_count() > blocks )
    {
        auto flow = static_cast<Flow*>(hash_table->first());
        assert(flow); // holds true because hash_table->get_count() > 0

        if ( (save_me and flow == save_me) or flow->was_blocked() or
            (flow->is_offloaded() and ignore_offloads) )
        {
            // check for non-null save_me above to silence analyzer
            // "called C++ object pointer is null" here
            if ( flow->was_blocked() )
                ++blocks;

            // FIXIT-M we should update last_data_seen upon touch to ensure
            // the hash_table LRU list remains sorted by time
            if ( !hash_table->touch() )
                break;
        }
        else
        {
            flow->ssn_state.session_flags |= SSNFLAG_PRUNED;
            release(flow, PruneReason::EXCESS);
            ++pruned;
        }
        if ( ignore_offloads > 0 )
            --ignore_offloads;
    }
    return pruned;
}

bool FlowCache::prune_one(PruneReason reason, bool do_cleanup)
{

    // so we don't prune the current flow (assume current == MRU)
    if ( hash_table->get_count() <= 1 )
        return false;

    auto flow = static_cast<Flow*>(hash_table->first());
    assert(flow);

    flow->ssn_state.session_flags |= SSNFLAG_PRUNED;
    release(flow, reason, do_cleanup);

    return true;
}

unsigned FlowCache::timeout(unsigned num_flows, time_t thetime)
{
    // FIXIT-H should Active be suspended here too?
    unsigned retired = 0;

    auto flow = static_cast<Flow*>(hash_table->current());

    if ( !flow )
        flow = static_cast<Flow*>(hash_table->first());

    while ( flow and (retired < num_flows) )
    {
        if ( flow->last_data_seen + config.nominal_timeout > thetime )
            break;

        if ( HighAvailabilityManager::in_standby(flow) or
            flow->is_offloaded() )
        {
            flow = static_cast<Flow*>(hash_table->next());
            continue;
        }

        flow->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
        release(flow, PruneReason::IDLE);

        ++retired;

        flow = static_cast<Flow*>(hash_table->current());
    }

    return retired;
}

// Remove all flows from the hash table.
unsigned FlowCache::purge()
{
    ActiveSuspendContext act_susp;
    FlagContext<decltype(flags)>(flags, SESSION_CACHE_FLAG_PURGING);

    unsigned retired = 0;

    while ( auto flow = static_cast<Flow*>(hash_table->first()) )
    {
        release(flow, PruneReason::NONE);
        ++retired;
    }

    return retired;
}

