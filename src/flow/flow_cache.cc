//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "flow_cache.h"

#include <cinttypes>
#include <numeric>
#include <sstream>

#include "control/control.h"
#include "detection/detection_engine.h"
#include "hash/hash_defs.h"
#include "hash/zhash.h"
#include "helpers/flag_context.h"
#include "helpers/policy_switcher.h"
#include "log/messages.h"
#ifdef REG_TEST
#include "main/analyzer.h"
#endif
#include "main/thread_config.h"
#include "packet_io/active.h"
#include "stream/base/stream_module.h"
#include "stream/stream_log.h"
#include "stream/tcp/tcp_session.h"
#include "stream/tcp/tcp_trace.h"
#include "time/packet_time.h"
#include "trace/trace_api.h"
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
static const unsigned WDT_MASK = 7; // kick watchdog once for every 8 flows deleted

//-------------------------------------------------------------------------
// FlowCache stuff
//-------------------------------------------------------------------------

FlowCache::FlowCache(const FlowCacheConfig& cfg) : config(cfg)
{
    hash_table = new ZHash(config.max_flows, sizeof(FlowKey), total_lru_count, false);
    uni_flows = new FlowUniList;
    uni_ip_flows = new FlowUniList;
    flags = 0x0;
    empty_lru_mask = ( 1 << max_protocols ) - 1;
    timeout_idx = first_proto;

    assert(prune_stats.get_total() == 0);
}

FlowCache::~FlowCache()
{
    delete hash_table;
    delete_uni();
}

unsigned FlowCache::get_flows_allocated() const
{
    return hash_table->get_num_nodes();
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
}

unsigned FlowCache::get_count()
{
    return hash_table ? hash_table->get_num_nodes() : 0;
}

Flow* FlowCache::find(const FlowKey* key)
{
    Flow* flow = (Flow*)hash_table->get_user_data(key,to_utype(key->pkt_type), false);
    if ( flow )
    {
        if ( flow->flags.in_allowlist )
            hash_table->touch_last_found(allowlist_lru_index);
        else
            hash_table->touch_last_found(to_utype(key->pkt_type));

        time_t t = packet_time();

        if ( flow->last_data_seen < t )
            flow->last_data_seen = t;
    }

    return flow;
}

// always prepend
void FlowCache::link_uni(Flow* flow)
{
    if ( flow->key->pkt_type == PktType::IP )
    {
        debug_logf(stream_trace, TRACE_FLOW, nullptr,
            "linking unidirectional flow (IP) to list of size: %u\n",
            uni_ip_flows->get_count());
        uni_ip_flows->link_uni(flow);
    }
    else
    {
        debug_logf(stream_trace, TRACE_FLOW, nullptr,
            "linking unidirectional flow (non-IP) to list of size: %u\n",
            uni_flows->get_count());
        uni_flows->link_uni(flow);
    }
}

// but remove from any point
void FlowCache::unlink_uni(Flow* flow)
{
    if ( flow->key->pkt_type == PktType::IP )
    {
        if ( uni_ip_flows->unlink_uni(flow) )
        {
            debug_logf(stream_trace, TRACE_FLOW, nullptr,
                "unlinked unidirectional flow (IP) from list, size: %u\n",
                uni_ip_flows->get_count());
        }
    }
    else
    {
        if ( uni_flows->unlink_uni(flow) )
        {
            debug_logf(stream_trace, TRACE_FLOW, nullptr,
                "unlinked unidirectional flow (non-IP) from list, size: %u\n",
                uni_flows->get_count());
        }
    }
}

Flow* FlowCache::allocate(const FlowKey* key)
{
    // This is called by packet processing and HA consume. This method is only called after a
    // failed attempt to find a flow with this key.
    time_t timestamp = packet_time();

#ifdef ALLOWLIST_MOVE_ON_EXCESS
    allowlist_on_excess_check(timestamp);
#endif

    if ( hash_table->get_num_nodes() >= config.max_flows )
    {
        flow_log("Flow: at max_flows limit (%u/%u), attempting to prune for new allocation\n",
            hash_table->get_num_nodes(), config.max_flows);

        unsigned pruned_idle = prune_idle(timestamp, nullptr);
        if ( !pruned_idle )
        {
            unsigned pruned_uni = prune_unis(key->pkt_type);
            if ( !pruned_uni )
            {
                unsigned pruned_excess = prune_excess(nullptr);
                if ( !pruned_excess )
                {
                    // CRITICAL: All pruning strategies failed
                    flow_log("Flow: CRITICAL - allocation at max capacity, no flows could be pruned "
                        "(idle=0, uni=0, excess=0), current=%u, max=%u\n",
                        hash_table->get_num_nodes(), config.max_flows);
                }
            }
        }
    }

    Flow* flow = new Flow;
    push(flow);

    flow = (Flow*)hash_table->get(key, to_utype(key->pkt_type));
    assert(flow);
    link_uni(flow);
    flow->last_data_seen = timestamp;
    flow->set_idle_timeout(config.proto[to_utype(flow->key->pkt_type)].nominal_timeout);
    empty_lru_mask &= ~(1ULL << to_utype(key->pkt_type)); // clear the bit for this protocol

    return flow;
}

void FlowCache::remove(Flow* flow)
{
    unlink_uni(flow);
    const snort::FlowKey* key = flow->key;
    uint8_t in_allowlist = flow->flags.in_allowlist;
    // Delete before releasing the node, so that the key is valid until the flow is completely freed
    delete flow;
    if ( in_allowlist )
        hash_table->release_node(key, allowlist_lru_index);
    else
        hash_table->release_node(key, to_utype(key->pkt_type));
}

bool FlowCache::release(Flow* flow, PruneReason reason, bool do_cleanup)
{
    PolicySwitcher psw(flow);

    if ( !flow->was_blocked() )
    {
        flow->flush(do_cleanup);
        if ( flow->ssn_state.session_flags & SSNFLAG_KEEP_FLOW )
        {
            flow->ssn_state.session_flags &= ~SSNFLAG_KEEP_FLOW;
            return false;
        }
    }

    if ( UNLIKELY(snort::PacketTracer::is_active() or snort::PacketTracer::is_daq_activated()) )
        log_flow_release(flow, reason);

    uint8_t in_allowlist = flow->flags.in_allowlist;
    flow->reset(do_cleanup);
    prune_stats.update(reason, ( in_allowlist ? static_cast<PktType>(allowlist_lru_index) : flow->key->pkt_type ));
    remove(flow);
    return true;
}

void FlowCache::retire(Flow* flow)
{
    PolicySwitcher psw(flow);
    flow->reset(true);
    prune_stats.update(PruneReason::NONE, flow->key->pkt_type);
    remove(flow);
}

unsigned FlowCache::prune_idle(time_t thetime, const Flow* save_me)
{
    ActiveSuspendContext act_susp(Active::ASP_PRUNE);

    unsigned pruned = 0;
    uint64_t checked_lrus_mask = empty_lru_mask;

    assert(max_protocols < 8 * sizeof(checked_lrus_mask));

    {
        PacketTracerSuspend pt_susp;
        while ( pruned <= cleanup_flows and 
                !all_lrus_checked(checked_lrus_mask) )
        {
            // Round-robin through the LRU types
            for( uint8_t lru_idx = first_proto; lru_idx < max_protocols; ++lru_idx )
            {
                if( pruned > cleanup_flows )
                    break;

                const uint64_t lru_mask = get_lru_mask(lru_idx);

                if( is_lru_checked(checked_lrus_mask, lru_mask) )
                    continue;

                auto flow = static_cast<Flow*>(hash_table->lru_first(lru_idx));
                if ( !flow )
                {
                    mark_lru_checked(checked_lrus_mask, empty_lru_mask, lru_mask);
                    continue;
                }
                
                if ( flow == save_me // Reached the current flow. This *should* be the newest flow
                    or flow->is_suspended()
                    or flow->last_data_seen + config.pruning_timeout >= thetime )
                {
                    mark_lru_checked(checked_lrus_mask, lru_mask);
                    continue;
                }

                flow->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
                if ( release(flow, PruneReason::IDLE_MAX_FLOWS) )
                    ++pruned;
            }
        }
    }

    if ( pruned )
        flow_log("Flow: Pruned idle %u flows\n", pruned);

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

    if ( pruned )
        flow_log("Flow: Pruned uni %u flows\n", pruned);

    return pruned;
}

unsigned FlowCache::prune_excess(const Flow* save_me)
{
    ActiveSuspendContext act_susp(Active::ASP_PRUNE);

    auto max_cap = config.max_flows - cleanup_flows;
    assert(max_cap > 0);

    unsigned pruned = 0;

    // Initially skip offloads but if that doesn't work, the hash table is iterated from the
    // beginning again. Prune offloads at that point.
    unsigned ignore_offloads = hash_table->get_num_nodes();
    uint64_t checked_lrus_mask = 0;

    assert(total_lru_count < 8 * sizeof(checked_lrus_mask));

    {
        uint8_t lru_idx = allowlist_lru_index;
        const uint8_t last_lru_idx = total_lru_count;
        PacketTracerSuspend pt_susp;
        unsigned blocks = 0;

        while ( true )
        {
            auto num_nodes = hash_table->get_num_nodes();
            if ( num_nodes <= max_cap or num_nodes <= blocks or
                ignore_offloads == 0 or all_lrus_checked(checked_lrus_mask) )
                break;

            for (; lru_idx < last_lru_idx; ++lru_idx)
            {
                num_nodes = hash_table->get_num_nodes();
                if ( num_nodes <= max_cap or num_nodes <= blocks )
                    break;

                const uint64_t lru_mask = get_lru_mask(lru_idx);

                if ( is_lru_checked(checked_lrus_mask, lru_mask) )
                    continue;

                auto flow = static_cast<Flow*>(hash_table->lru_first(lru_idx));
                if ( !flow )
                {
                    mark_lru_checked(checked_lrus_mask, lru_mask);
                    continue;
                }

                if ( (save_me and flow == save_me) or flow->was_blocked() or
                        (flow->is_suspended() and ignore_offloads) )
                {
                    if ( flow->was_blocked() )
                        ++blocks;

                    hash_table->lru_touch(lru_idx);
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

            if ( lru_idx >= last_lru_idx )
                lru_idx = first_proto;
        }

        if ( !pruned and hash_table->get_num_nodes() > max_cap )
        {
            pruned += prune_multiple(PruneReason::EXCESS, true);
        }
    }

    if ( pruned )
        flow_log("Flow: Pruned excess %u flows\n", pruned);
    return pruned;
}

bool FlowCache::prune_one(PruneReason reason, bool do_cleanup, uint8_t type)
{
    if (hash_table->get_num_nodes() <= 1)
        return false;

    auto flow = static_cast<Flow*>(hash_table->lru_first(type));

    if ( !flow )
        return false;

    flow->ssn_state.session_flags |= SSNFLAG_PRUNED;

    bool flow_handled;
    if ( handle_allowlist_pruning(flow, reason, type, flow_handled) )
        return flow_handled;

    return release(flow, reason, do_cleanup);
}

unsigned FlowCache::prune_multiple(PruneReason reason, bool do_cleanup)
{
    unsigned pruned = 0;
    // so we don't prune the current flow (assume current == MRU)
    if ( hash_table->get_num_nodes() <= 1 )
        return 0;

    uint8_t lru_idx = 0;
    uint64_t checked_lrus_mask = 0;

    assert(max_protocols < 8 * sizeof(checked_lrus_mask));

    if ( reason == PruneReason::MEMCAP or reason == PruneReason::EXCESS )
    {
        while ( pruned < config.prune_flows )
        {
            if ( !prune_one(reason, do_cleanup, allowlist_lru_index) )
                break;
            pruned++;
        }
    }

    while ( pruned < config.prune_flows )
    {
        const uint64_t lru_mask = get_lru_mask(lru_idx);
        if ( is_lru_checked(checked_lrus_mask, lru_mask) or !prune_one(reason, do_cleanup, lru_idx) )
        {
            mark_lru_checked(checked_lrus_mask, lru_mask);

            if ( all_lrus_checked(checked_lrus_mask) )
                break;
        }
        else
            pruned++;

        if ( ++lru_idx >= max_protocols )
            lru_idx = 0;
    }

    if ( pruned )
        flow_log("Flow: Pruned memcap %u flows\n", pruned);

    return pruned;
}

unsigned FlowCache::timeout(unsigned num_flows, time_t thetime)
{
    ActiveSuspendContext act_susp(Active::ASP_TIMEOUT);

    unsigned retired = 0;
    uint64_t checked_lrus_mask = empty_lru_mask;  // Start by skipping any protocols that have no flows.

#ifdef REG_TEST
    if ( hash_table->get_node_count(allowlist_lru_index) > 0 )
    {
        uint64_t allowlist_timeout_count = 0;
        const Flow* flow = static_cast<Flow*>(hash_table->lru_first(allowlist_lru_index));
        while ( flow )
        {
            if ( flow->last_data_seen + flow->idle_timeout > thetime )
                allowlist_timeout_count++;
            flow = static_cast<Flow*>(hash_table->lru_next(allowlist_lru_index));
        }
        if ( allowlist_timeout_count )
            flow_log("Flow: %" PRIu64 " allowlist flow(s) timed out but not pruned \n", allowlist_timeout_count);
    }
#endif

    assert(max_protocols < 8 * sizeof(checked_lrus_mask));

    {
        PacketTracerSuspend pt_susp;

        while ( retired < num_flows and !all_lrus_checked(checked_lrus_mask) )
        {
            for( ; timeout_idx < max_protocols; ++timeout_idx ) 
            {

                const uint64_t lru_mask = get_lru_mask(timeout_idx);

                if ( is_lru_checked(checked_lrus_mask, lru_mask) )
                    continue;

                auto flow = static_cast<Flow*>(hash_table->lru_current(timeout_idx));
                if ( !flow )
                {
                    flow = static_cast<Flow*>(hash_table->lru_first(timeout_idx));
                    if ( !flow )
                    {
                        mark_lru_checked(checked_lrus_mask, empty_lru_mask, lru_mask);
                        continue;
                    }
                }

                if ( flow->is_hard_expiration() )
                {
                    if ( flow->expire_time > static_cast<uint64_t>(thetime) )
                    {
                        mark_lru_checked(checked_lrus_mask, lru_mask);
                        continue;
                    }
                }
                else if ( flow->last_data_seen + flow->idle_timeout > thetime )
                {
                    mark_lru_checked(checked_lrus_mask, lru_mask);
                    continue;
                }

                if ( HighAvailabilityManager::in_standby(flow) or flow->is_suspended() )
                    continue;

                flow->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
                if ( release(flow, PruneReason::IDLE_PROTOCOL_TIMEOUT) )
                {
                    if( ++retired >= num_flows )
                        break;
                }
            }

            timeout_idx = first_proto;
        }
    }

    if ( retired )
        flow_log("Flow: Timed out %u flows\n", retired);

    return retired;
}

unsigned FlowCache::delete_active_flows(unsigned mode, unsigned num_to_delete, unsigned &deleted)
{
    uint64_t checked_lrus_mask = empty_lru_mask;
    uint64_t undeletable = 0;

    assert(max_protocols < 8 * sizeof(checked_lrus_mask));


    while ( num_to_delete and !all_lrus_checked(checked_lrus_mask) and
            undeletable < hash_table->get_num_nodes() )
    {
        for ( uint8_t lru_idx = first_proto; lru_idx < max_protocols; ++lru_idx )
        {
            if ( num_to_delete == 0 )
                break;

            const uint64_t lru_mask = get_lru_mask(lru_idx);

            if ( is_lru_checked(checked_lrus_mask, lru_mask) )
                continue;

            auto flow = static_cast<Flow*>(hash_table->lru_first(lru_idx));
            if ( !flow )
            {
                mark_lru_checked(checked_lrus_mask, empty_lru_mask, lru_mask);
                continue;
            }

            if ( (mode == ALLOWED_FLOWS_ONLY and (flow->was_blocked() or flow->is_suspended()))
                or (mode == OFFLOADED_FLOWS_TOO and flow->was_blocked()) )
            {
                undeletable++;
                hash_table->lru_touch(lru_idx);
                continue;
            }

            if ( (deleted & WDT_MASK) == 0 )
                ThreadConfig::preemptive_kick();

            unlink_uni(flow);

            if ( flow->was_blocked() )
                delete_stats.update(FlowDeleteState::BLOCKED);
            else if ( flow->is_suspended() )
                delete_stats.update(FlowDeleteState::OFFLOADED);
            else
                delete_stats.update(FlowDeleteState::ALLOWED);

            flow->reset(true);
            // Delete before removing the node, so that the key is valid until the flow is completely freed
            delete flow;
            // The flow should not be removed from the hash before reset
            hash_table->remove(lru_idx);
            ++deleted;
            --num_to_delete;
        }
    }
    return num_to_delete;
}

unsigned FlowCache::delete_flows(unsigned num_to_delete)
{
    ActiveSuspendContext act_susp(Active::ASP_RELOAD);

    unsigned deleted = 0;

    {
        PacketTracerSuspend pt_susp;

        for ( unsigned mode = ALLOWED_FLOWS_ONLY; num_to_delete && mode <= ALL_FLOWS; ++mode )
            num_to_delete = delete_active_flows(mode, num_to_delete, deleted);
    }

    if ( deleted )
        flow_log("Flow: Deleted %u flows\n", deleted);

    return deleted;
}

// Remove all flows from the hash table.
unsigned FlowCache::purge()
{
    ActiveSuspendContext act_susp(Active::ASP_EXIT);
    FlagContext<decltype(flags)>(flags, SESSION_CACHE_FLAG_PURGING);

    unsigned retired = 0;

    for( uint8_t proto_idx = first_proto; proto_idx < total_lru_count; ++proto_idx ) 
    {
        while ( auto flow = static_cast<Flow*>(hash_table->lru_first(proto_idx)) )
        {
            retire(flow);
            ++retired;
        }
    }
    // Remove these here so alloc/dealloc counts are right when Memory::get_pegs is called
    delete_uni();
    return retired;
}

#ifdef ALLOWLIST_MOVE_ON_EXCESS
static inline bool is_excess_admission_eligible(snort::Flow* f)
{
    return !f->was_blocked() and !f->cannot_trust()
        and f->flow_state != snort::Flow::FlowState::BLOCK
        and f->flow_state != snort::Flow::FlowState::RESET
        and !f->is_suspended()
        and !HighAvailabilityManager::in_standby(f);
}
#endif

bool FlowCache::allowlist_on_excess(snort::Flow *f)
{
#ifdef ALLOWLIST_MOVE_ON_EXCESS
    if ( is_allowlist_on_excess() and is_excess_admission_eligible(f) )
    {
        Stream::disable_reassembly(f);
        f->free_flow_data();
        f->trust();
        f->last_verdict = DAQ_VERDICT_WHITELIST;
        if ( move_to_allowlist(f) )
        {
            excess_to_allowlist_count++;
            f->flags.allowed_on_excess = true;
            return true;
        }
    }
    else if ( config.move_to_allowlist_on_excess and !config.allowlist_cache )
        flow_log("Flow: Warning! move_to_allowlist_on_excess is enabled with no allowlist cache\n");
#else
    (void)f;
#endif
    return false;
}

void FlowCache::allowlist_on_excess_check(time_t now)
{
#ifndef ALLOWLIST_MOVE_ON_EXCESS
    (void)now;
#else
    if ( !is_allowlist_on_excess() )
        return;
    if ( hash_table->get_num_nodes() <
         config.max_flows - config.allowlist_max_excess_flows )
        return;

    const uint8_t candidate_lrus[] = { to_utype(PktType::TCP), to_utype(PktType::UDP) };
    bool admitted = false;
    for ( uint8_t lru_idx : candidate_lrus )
    {
        unsigned scanned = 0;
        auto* victim = static_cast<Flow*>(hash_table->lru_first(lru_idx));
        while ( victim and scanned < allowlist_admission_scan_cap )
        {
            const bool expired = now > 0 and
                ( victim->is_hard_expiration()
                  ? victim->expire_time <= static_cast<uint64_t>(now)
                  : ( victim->idle_timeout > 0 and
                      victim->last_data_seen + victim->idle_timeout <= now ) or
                    ( config.pruning_timeout > 0 and
                      victim->last_data_seen + config.pruning_timeout < now ) );
            const bool suspended = victim->is_suspended();
            const bool standby = HighAvailabilityManager::in_standby(victim);

            if ( expired and !suspended and !standby )
                return;

            if ( !expired and is_excess_admission_eligible(victim) and
                 allowlist_on_excess(victim) )
            {
                admitted = true;
                break;
            }
            victim = static_cast<Flow*>(hash_table->lru_next(lru_idx));
            ++scanned;
        }
        if ( admitted )
            break;
        if ( scanned == allowlist_admission_scan_cap )
        {
            const auto* head = static_cast<Flow*>(hash_table->lru_first(lru_idx));
            if ( head )
                hash_table->lru_touch(lru_idx);
        }
    }
#endif
}

bool FlowCache::handle_allowlist_pruning(snort::Flow* flow, PruneReason reason, uint8_t type, bool& flow_handled)
{
    flow_handled = true;

    if ( type == allowlist_lru_index )
    {
        if ( reason == PruneReason::EXCESS or reason == PruneReason::MEMCAP )
            return false;
        flow_handled = false;
        return true;
    }

    // EXCESS admission is proactive (allocate); at prune time EXCESS hard-prunes.
    (void)flow;
    return false;
}

static std::string timeout_to_str(time_t t)
{
    std::stringstream out;
    time_t hours = t / (60 * 60);

    if (hours)
    {
        out << hours << "h";
        t -= hours * (60 * 60);
    }

    time_t minutes = t / 60;
    if (minutes || hours)
    {
        out << minutes << "m";
        t -= minutes * 60;
    }

    if (t || !hours)
        out << t << "s";

    return out.str();
}

template<typename StreamType>
void FlowCache::output_flow(StreamType& stream, const Flow& flow, const struct timeval& now) const
{
    char src_ip[INET6_ADDRSTRLEN];
    src_ip[0] = 0;
    char dst_ip[INET6_ADDRSTRLEN];
    dst_ip[0] = 0;
    uint16_t src_port;
    uint16_t dst_port;
    if (flow.flags.key_is_reversed)
    {
        SfIp ip;
        ip.set(flow.key->ip_h);
        ip.ntop(src_ip, sizeof(src_ip));
        ip.set(flow.key->ip_l);
        ip.ntop(dst_ip, sizeof(dst_ip));
        src_port = flow.key->port_h;
        dst_port = flow.key->port_l;
    }
    else
    {
        SfIp ip;
        ip.set(flow.key->ip_l);
        ip.ntop(src_ip, sizeof(src_ip));
        ip.set(flow.key->ip_h);
        ip.ntop(dst_ip, sizeof(dst_ip));
        src_port = flow.key->port_l;
        dst_port = flow.key->port_h;
    }
    std::stringstream out;
    std::stringstream proto;
    switch ( flow.key->pkt_type )
    {
        case PktType::IP:
            out << "Instance-ID: " << get_relative_instance_number() << " IP " << flow.key->addressSpaceId << ": " << src_ip << " " << dst_ip;
            break;

        case PktType::ICMP:
            out << "Instance-ID: " << get_relative_instance_number() << " ICMP " << flow.key->addressSpaceId << ": " << src_ip << " type " << src_port << " "
                << dst_ip;
            break;

        case PktType::TCP:
            out << "Instance-ID: " << get_relative_instance_number() << " TCP " << flow.key->addressSpaceId << ": " << src_ip << "/" << src_port << " "
                << dst_ip << "/" << dst_port;
            if (flow.session)
            {
                TcpSession* tcp_session = static_cast<TcpSession*>(flow.session);
                proto << " state client " << stream_tcp_state_to_str(tcp_session->client)
                    << " server " << stream_tcp_state_to_str(tcp_session->server);
            }
            break;

        case PktType::UDP:
            out << "Instance-ID: " << get_relative_instance_number() << " UDP " << flow.key->addressSpaceId << ": "<< src_ip << "/" << src_port << " "
                << dst_ip << "/" << dst_port;
            break;

        default:
            assert(false);
    }
    int remaining_time = (flow.last_data_seen + flow.idle_timeout) - now.tv_sec;
    std::string display_str = ( remaining_time < 0 ) ?  "s, timed out for " : "s, timeout in ";
    out << " pkts/bytes client " << flow.flowstats.client_pkts << "/" << flow.flowstats.client_bytes
        << " server " << flow.flowstats.server_pkts << "/" << flow.flowstats.server_bytes
        << " idle " << (now.tv_sec - flow.last_data_seen) << "s, uptime "
        << (now.tv_sec - flow.flowstats.start_time.tv_sec) << display_str;
    std::string t = flow.is_hard_expiration() ?
        timeout_to_str(abs((int)(flow.expire_time - now.tv_sec))) :
        timeout_to_str(abs(remaining_time));
    out << t;
    std::string allow_s;
    if ( flow.flags.allowed_on_excess )
        allow_s = " (allowlist on excess)";
    else if ( flow.flags.in_allowlist )
        allow_s = " (allowlist)";
    stream << out.str() << proto.str() << allow_s << std::endl;
}

size_t FlowCache::uni_flows_size() const
{
    return uni_flows ? uni_flows->get_count() : 0;
}

size_t FlowCache::uni_ip_flows_size() const
{
    return uni_ip_flows ? uni_ip_flows->get_count() : 0;
}

size_t FlowCache::flows_size() const
{
    return hash_table->get_num_nodes();
}

PegCount FlowCache::get_lru_flow_count(uint8_t lru_idx) const
{ 
    return hash_table->get_node_count(lru_idx); 
}

bool FlowCache::move_to_allowlist(snort::Flow* f)
{
    if( hash_table->switch_lru_cache(f->key, to_utype(f->key->pkt_type), allowlist_lru_index) )
    {
        f->flags.in_allowlist = 1;
        return true;
    }
    return false;
}

#ifdef UNIT_TEST
size_t FlowCache::count_flows_in_lru(uint8_t lru_index) const
{
    size_t count = 0;
    const Flow* flow = static_cast<Flow*>(hash_table->get_walk_user_data(lru_index));
    while (flow)
    {
        ++count;
        flow = static_cast<Flow*>(hash_table->get_next_walk_user_data(lru_index));
    }
    return count;
}
#endif

inline void FlowCache::log_flow_release(const snort::Flow* flow, PruneReason reason) const
{
    PacketTracerUnsuspend pt_unsusp;

    std::stringstream temp_stream;
    struct timeval now;

    packet_gettimeofday(&now);
    output_flow(temp_stream, *flow, now);
    std::string flow_info = temp_stream.str();

    flow_log("Flow: Releasing flow due to %s: %s", prune_reason_to_string(reason), flow_info.c_str());
}
