//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
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

#include "flow/flow_cache.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hash/zhash.h"
#include "helpers/flag_context.h"
#include "ips_options/ips_flowbits.h"
#include "main/snort_debug.h"
#include "packet_io/active.h"
#include "time/packet_time.h"

#define SESSION_CACHE_FLAG_PURGING  0x01

uint64_t PruneStats::get_total() const
{
    uint64_t total = 0;
    for ( reason_t i = 0;
          i < static_cast<reason_t>(PruneReason::MAX); ++i )
    {
        total += prunes[i];
    }

    return total;
}

//-------------------------------------------------------------------------
// FlowCache stuff
//-------------------------------------------------------------------------

FlowCache::FlowCache (
    const FlowConfig& cfg, uint32_t cleanup_count, uint32_t cleanup_percent) :
    config(cfg), memcap(cfg.mem_cap)
{
    if (cleanup_percent)
        cleanup_flows = config.max_sessions * cleanup_percent/100;

    else
        cleanup_flows = cleanup_count;

    if ( cleanup_flows >= cfg.max_sessions )
        cleanup_flows = cfg.max_sessions - 1;

    if ( !cleanup_flows )
        cleanup_flows = 1;

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

int FlowCache::get_count()
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

int FlowCache::release(Flow* flow, PruneReason reason)
{
    flow->reset();
    prune_stats.update(reason);
    return remove(flow);
}

int FlowCache::remove(Flow* flow)
{
    if ( flow->next )
        unlink_uni(flow);

    return hash_table->remove(flow->key);
}

uint32_t FlowCache::prune_stale(uint32_t thetime, const Flow* save_me)
{
    ActiveSuspendContext act_susp;

    uint32_t pruned = 0;
    auto flow = static_cast<Flow*>(hash_table->first());

    while ( flow and pruned <= cleanup_flows )
    {
#if 0
        // FIXIT-L this loops forever if 1 flow in cache
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
        if ( flow->last_data_seen + config.pruning_timeout >= thetime )
            break;

        DebugMessage(DEBUG_STREAM, "pruning stale flow\n");
        flow->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
        release(flow, PruneReason::TIMEOUT);
        ++pruned;

        flow = static_cast<Flow*>(hash_table->first());
    }

    return pruned;
}

uint32_t FlowCache::prune_unis()
{
    ActiveSuspendContext act_susp;

    // we may have many or few unis; need to find reasonable ratio
    // FIXIT-L max_uni should be based on typical ratios seen in perfmon
    const uint32_t max_uni = (config.max_sessions >> 2) + 1;

    Flow* curr = uni_tail->prev;
    uint32_t pruned = 0;

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

uint32_t FlowCache::prune_excess(const Flow* save_me)
{
    ActiveSuspendContext act_susp;

    auto max_cap = config.max_sessions - cleanup_flows;
    assert(max_cap > 0);

    uint32_t pruned = 0;
    uint32_t blocks = 0;

    while ( hash_table->get_count() > max_cap and hash_table->get_count() > blocks )
    {
        auto flow = static_cast<Flow*>(hash_table->first());
        assert(flow); // holds true because hash_table->get_count() > 0

        if ( flow == save_me or flow->was_blocked() )
        {
            if ( flow->was_blocked() )
                ++blocks;

            // FIXIT-M J we should update last_data_seen upon touch to ensure
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
    }

    return pruned;
}

bool FlowCache::prune_one(PruneReason reason)
{
    // so we don't prune the current flow (assume current == MRU)
    if ( hash_table->get_count() <= 1 )
        return false;

    auto flow = static_cast<Flow*>(hash_table->first());
    assert(flow);

    flow->ssn_state.session_flags |= SSNFLAG_PRUNED;
    release(flow, reason);

    return true;
}

void FlowCache::timeout(uint32_t num_flows, time_t thetime)
{
    uint32_t retired = 0;

    auto flow = static_cast<Flow*>(hash_table->current());

    if ( !flow )
        flow = static_cast<Flow*>(hash_table->first());

    while ( flow and retired < num_flows )
    {
        if ( flow->last_data_seen + config.nominal_timeout > thetime )
            break;

        DebugMessage(DEBUG_STREAM, "retiring stale flow\n");
        flow->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
        release(flow, PruneReason::TIMEOUT);

        ++retired;

        flow = static_cast<Flow*>(hash_table->current());
    }
}

// Remove all flows from the hash table.
int FlowCache::purge()
{
    ActiveSuspendContext act_susp;
    FlagContext<decltype(flags)>(flags, SESSION_CACHE_FLAG_PURGING);

    uint32_t retired = 0;

    while ( auto flow = static_cast<Flow*>(hash_table->first()) )
    {
        flow->ssn_state.session_flags |= SSNFLAG_PRUNED;
        release(flow, PruneReason::PURGE);
        ++retired;
    }

    return retired;
}

