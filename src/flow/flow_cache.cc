//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/detection_engine.h"
#include "hash/hash_defs.h"
#include "hash/zhash.h"
#include "helpers/flag_context.h"
#include "ips_options/ips_flowbits.h"
#include "memory/memory_cap.h"
#include "packet_io/active.h"
#include "packet_tracer/packet_tracer.h"
#include "time/packet_time.h"
#include "utils/stats.h"

#include "flow.h"
#include "flow_key.h"
#include "flow_uni_list.h"
#include "ha.h"
#include "session.h"

using namespace snort;

#define SESSION_CACHE_FLAG_PURGING  0x01

static const unsigned ALLOWED_FLOWS_ONLY = 1;
static const unsigned OFFLOADED_FLOWS_TOO = 2;
static const unsigned ALL_FLOWS = 3;

//-------------------------------------------------------------------------
// FlowCache stuff
//-------------------------------------------------------------------------

THREAD_LOCAL bool FlowCache::pruning_in_progress = false;

FlowCache::FlowCache(const FlowCacheConfig& cfg) : config(cfg)
{
    hash_table = new ZHash(config.max_flows, sizeof(FlowKey));
    uni_flows = new FlowUniList;
    uni_ip_flows = new FlowUniList;
    flags = 0x0;

    assert(prune_stats.get_total() == 0);
}

FlowCache::~FlowCache()
{
    delete hash_table;
    delete_uni();
}

void FlowCache::delete_uni()
{
    delete uni_flows;
    delete uni_ip_flows;

    uni_flows = nullptr;
    uni_ip_flows = nullptr;
}

void FlowCache::push(Flow* flow)
{
    void* key = hash_table->push(flow);
    flow->key = (FlowKey*)key;
    ++flows_allocated;
}

unsigned FlowCache::get_count()
{
    return hash_table ? hash_table->get_num_nodes() : 0;
}

Flow* FlowCache::find(const FlowKey* key)
{
    Flow* flow = (Flow*)hash_table->get_user_data(key);

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
    if ( flow->pkt_type == PktType::IP )
        uni_ip_flows->link_uni(flow);
    else
        uni_flows->link_uni(flow);
}

// but remove from any point
void FlowCache::unlink_uni(Flow* flow)
{
    if ( flow->pkt_type == PktType::IP )
        uni_ip_flows->unlink_uni(flow);
    else
        uni_flows->unlink_uni(flow);
}

Flow* FlowCache::allocate(const FlowKey* key)
{
    time_t timestamp = packet_time();
    Flow* flow = (Flow*)hash_table->get(key);
    if ( !flow )
    {
        if ( flows_allocated < config.max_flows )
        {
            Flow* new_flow = new Flow();
            push(new_flow);
            memory::MemoryCap::update_allocations(sizeof(HashNode) + sizeof(FlowKey));
        }
        else if ( !prune_stale(timestamp, nullptr) )
        {
            if ( !prune_unis(key->pkt_type) )
                prune_excess(nullptr);
        }

        flow = (Flow*)hash_table->get(key);
        assert(flow);

        if ( flow->session && flow->pkt_type != key->pkt_type )
            flow->term();
        else
            flow->reset();
    }

    link_uni(flow);
    if ( flow->session && flow->pkt_type != key->pkt_type )
        flow->term();

    memory::MemoryCap::update_allocations(config.proto[to_utype(key->pkt_type)].cap_weight);
    flow->last_data_seen = timestamp;

    return flow;
}

void FlowCache::remove(Flow* flow)
{
    if ( flow->next )
        unlink_uni(flow);

    // FIXIT-M This check is added for offload case where both Flow::reset
    // and Flow::retire try remove the flow from hash. Flow::reset should
    // just mark the flow as pending instead of trying to remove it.
    if ( !hash_table->release_node(flow->key) )
        memory::MemoryCap::update_deallocations(config.proto[to_utype(flow->key->pkt_type)].cap_weight);
}

bool FlowCache::release(Flow* flow, PruneReason reason, bool do_cleanup)
{
    assert(!pruning_in_progress);
    pruning_in_progress = true;

    if ( !flow->was_blocked() )
    {
        flow->flush(do_cleanup);
        if ( flow->ssn_state.session_flags & SSNFLAG_KEEP_FLOW )
        {
            flow->ssn_state.session_flags &= ~SSNFLAG_KEEP_FLOW;
            pruning_in_progress = false;
            return false;
        }
    }

    flow->reset(do_cleanup);
    prune_stats.update(reason);
    remove(flow);
    pruning_in_progress = false;
    return true;
}

void FlowCache::retire(Flow* flow)
{
    flow->reset(true);
    flow->term();
    prune_stats.update(PruneReason::NONE);
    remove(flow);
}

unsigned FlowCache::prune_stale(uint32_t thetime, const Flow* save_me)
{
    ActiveSuspendContext act_susp(Active::ASP_PRUNE);

    unsigned pruned = 0;
    auto flow = static_cast<Flow*>(hash_table->lru_first());

    {
        PacketTracerSuspend pt_susp;

        while ( flow and pruned <= cleanup_flows )
        {
#if 0
            // FIXIT-RC this loops forever if 1 flow in cache
            if (flow == save_me)
            {
                break;
                if ( hash_table->get_count() == 1 )
                    break;

                hash_table->lru_touch();
            }
#else
            // Reached the current flow. This *should* be the newest flow
            if ( flow == save_me )
                break;
#endif
            if ( flow->is_suspended() )
                break;

            if ( flow->last_data_seen + config.pruning_timeout >= thetime )
                break;

            flow->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
            if ( release(flow, PruneReason::IDLE) )
                ++pruned;

            flow = static_cast<Flow*>(hash_table->lru_first());
        }
    }

    if ( PacketTracer::is_active() and pruned )
        PacketTracer::log("Flow: Pruned %u flows\n", pruned);

    return pruned;
}

unsigned FlowCache::prune_unis(PktType pkt_type)
{
    ActiveSuspendContext act_susp(Active::ASP_PRUNE);

    // we may have many or few unis; need to find reasonable ratio
    // FIXIT-M max_uni should be based on typical ratios seen in perfmon
    const unsigned max_uni = (config.max_flows >> 2) + 1;
    unsigned pruned = 0;
    FlowUniList* uni_list;

    {
        PacketTracerSuspend pt_susp;

        if ( pkt_type == PktType::IP )
            uni_list = uni_ip_flows;
        else
            uni_list = uni_flows;

        Flow* flow = uni_list->get_oldest_uni();
        while ( (uni_list->get_count() > max_uni) && flow && (pruned < cleanup_flows) )
        {
            Flow* prune_me = flow;
            flow = uni_list->get_prev(prune_me);

            if ( prune_me->was_blocked() )
                continue;

            if ( release(prune_me, PruneReason::UNI) )
                ++pruned;
        }
    }

    if ( PacketTracer::is_active() and pruned )
        PacketTracer::log("Flow: Pruned %u flows\n", pruned);

    return pruned;
}

unsigned FlowCache::prune_excess(const Flow* save_me)
{
    ActiveSuspendContext act_susp(Active::ASP_PRUNE);

    auto max_cap = config.max_flows - cleanup_flows;
    assert(max_cap > 0);

    unsigned pruned = 0;

    // initially skip offloads but if that doesn't work the hash table is iterated from the
    // beginning again. prune offloads at that point.
    unsigned ignore_offloads = hash_table->get_num_nodes();

    {
        PacketTracerSuspend pt_susp;
        unsigned blocks = 0;

        while ( hash_table->get_num_nodes() > max_cap and hash_table->get_num_nodes() > blocks )
        {
            auto flow = static_cast<Flow*>(hash_table->lru_first());
            assert(flow); // holds true because hash_table->get_count() > 0

            if ( (save_me and flow == save_me) or flow->was_blocked() or
                    (flow->is_suspended() and ignore_offloads) )
            {
                // check for non-null save_me above to silence analyzer
                // "called C++ object pointer is null" here
                if ( flow->was_blocked() )
                    ++blocks;

                // FIXIT-M we should update last_data_seen upon touch to ensure
                // the hash_table LRU list remains sorted by time
                hash_table->lru_touch();
            }
            else
            {
                flow->ssn_state.session_flags |= SSNFLAG_PRUNED;
                if ( release(flow, PruneReason::EXCESS) )
                    ++pruned;
            }
            if ( ignore_offloads > 0 )
                --ignore_offloads;
        }

        if (!pruned and hash_table->get_num_nodes() > max_cap)
        {
            prune_one(PruneReason::EXCESS, true);
            ++pruned;
        }
    }

    if ( PacketTracer::is_active() and pruned )
        PacketTracer::log("Flow: Pruned %u flows\n", pruned);

    return pruned;
}

bool FlowCache::prune_one(PruneReason reason, bool do_cleanup)
{
    // so we don't prune the current flow (assume current == MRU)
    if ( hash_table->get_num_nodes() <= 1 )
        return false;

    // ZHash returns in LRU order, which is updated per packet via find --> move_to_front call
    auto flow = static_cast<Flow*>(hash_table->lru_first());
    assert(flow);

    flow->ssn_state.session_flags |= SSNFLAG_PRUNED;
    release(flow, reason, do_cleanup);

    return true;
}

unsigned FlowCache::timeout(unsigned num_flows, time_t thetime)
{
    ActiveSuspendContext act_susp(Active::ASP_TIMEOUT);

    unsigned retired = 0;

    {
        PacketTracerSuspend pt_susp;

        auto flow = static_cast<Flow*>(hash_table->lru_current());

        if ( !flow )
            flow = static_cast<Flow*>(hash_table->lru_first());

        while ( flow and (retired < num_flows) )
        {
            if ( flow->is_hard_expiration() )
            {
                if ( flow->expire_time > (uint64_t) thetime )
                    break;
            }
            else if ( flow->last_data_seen + config.proto[to_utype(flow->key->pkt_type)].nominal_timeout > thetime )
                break;

            if ( HighAvailabilityManager::in_standby(flow) or
                    flow->is_suspended() )
            {
                flow = static_cast<Flow*>(hash_table->lru_next());
                continue;
            }

            flow->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
            if ( release(flow, PruneReason::IDLE) )
                ++retired;

            flow = static_cast<Flow*>(hash_table->lru_current());
        }
    }

    if ( PacketTracer::is_active() and retired )
        PacketTracer::log("Flow: Timed out %u flows\n", retired);

    return retired;
}

unsigned FlowCache::delete_active_flows(unsigned mode, unsigned num_to_delete, unsigned &deleted)
{
    unsigned flows_to_check = hash_table->get_num_nodes();
    while ( num_to_delete && flows_to_check-- )
    {
        auto flow = static_cast<Flow*>(hash_table->lru_first());
        assert(flow);
        if ( (mode == ALLOWED_FLOWS_ONLY and (flow->was_blocked() || flow->is_suspended()))
                or (mode == OFFLOADED_FLOWS_TOO and flow->was_blocked()) )
        {
            hash_table->lru_touch();
            continue;
        }

        // we have a winner...
        if ( flow->next )
            unlink_uni(flow);

        if ( flow->was_blocked() )
            delete_stats.update(FlowDeleteState::BLOCKED);
        else if ( flow->is_suspended() )
            delete_stats.update(FlowDeleteState::OFFLOADED);
        else
            delete_stats.update(FlowDeleteState::ALLOWED);

        flow->reset(true);
        //The flow should not be removed from the hash before reset
        hash_table->remove();
        delete flow;
        memory::MemoryCap::update_deallocations(sizeof(HashNode) + sizeof(FlowKey));
        --flows_allocated;
        ++deleted;
        --num_to_delete;
    }

    return num_to_delete;
}

unsigned FlowCache::delete_flows(unsigned num_to_delete)
{
    ActiveSuspendContext act_susp(Active::ASP_RELOAD);

    unsigned deleted = 0;

    {
        PacketTracerSuspend pt_susp;

        // delete from the free list first...
        while ( num_to_delete )
        {
            Flow* flow = (Flow*)hash_table->pop();
            if ( !flow )
                break;

            delete flow;
            delete_stats.update(FlowDeleteState::FREELIST);
            memory::MemoryCap::update_deallocations(sizeof(HashNode) + sizeof(FlowKey));

            --flows_allocated;
            ++deleted;
            --num_to_delete;
        }

        unsigned mode = ALLOWED_FLOWS_ONLY;
        while ( num_to_delete && mode <= ALL_FLOWS )
            num_to_delete = delete_active_flows(mode++, num_to_delete, deleted);
    }

    if ( PacketTracer::is_active() and deleted )
        PacketTracer::log("Flow: Deleted %u flows\n", deleted);

    return deleted;
}

// Remove all flows from the hash table.
unsigned FlowCache::purge()
{
    ActiveSuspendContext act_susp(Active::ASP_EXIT);
    FlagContext<decltype(flags)>(flags, SESSION_CACHE_FLAG_PURGING);

    unsigned retired = 0;
    assert(!pruning_in_progress);
    pruning_in_progress = true;
    while ( auto flow = static_cast<Flow*>(hash_table->lru_first()) )
    {
        retire(flow);
        ++retired;
    }
    pruning_in_progress = false;

    while ( Flow* flow = (Flow*)hash_table->pop() )
    {
        delete flow;
        memory::MemoryCap::update_deallocations(sizeof(HashNode) + sizeof(FlowKey));
        --flows_allocated;
    }

    // Remove these here so alloc/dealloc counts are right when Memory::get_pegs is called
    delete_uni();

    return retired;
}
