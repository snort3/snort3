/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
** AUTHOR: Steven Sturges <ssturges@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "flow/flow_cache.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "packet_io/active.h"
#include "packet_time.h"
#include "ips_options/ips_flowbits.h"
#include "stream5/stream_common.h"
#include "stream5/stream_ha.h"
#include "zhash.h"

#define SESSION_CACHE_FLAG_PURGING  0x01
#define SESSION_CACHE_FLAG_PRUNING  0x02  // FIXIT not used?

//-------------------------------------------------------------------------
// FlowCache stuff
//-------------------------------------------------------------------------

FlowCache::FlowCache (
    int max,
    uint32_t flow_timeout_min,
    uint32_t flow_timeout_max,
    uint32_t cleanup_count,
    uint32_t cleanup_percent)
{
    timeoutAggressive = flow_timeout_min;
    timeoutNominal = flow_timeout_max;
    max_flows = max;

    if (cleanup_percent)
        cleanup_flows = max_flows * cleanup_percent/100;

    else
        cleanup_flows = cleanup_count;

    if ( !cleanup_flows )
        cleanup_flows = 1;

    hash_table = new ZHash(max_flows, sizeof(FlowKey));
    hash_table->set_keyops(FlowKey::hash, FlowKey::compare);

    uni_head = new Flow;
    uni_tail = new Flow;

    uni_head->next = uni_tail;
    uni_tail->prev = uni_head;

    prunes = uni_count = 0;
    flags = 0x0;
}

FlowCache::~FlowCache ()
{
    purge();

    while ( Flow* flow = (Flow*)hash_table->pop() )
        delete flow;

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

Flow* FlowCache::get(const FlowKey *key)
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
void FlowCache::link_uni (Flow* flow)
{
    flow->next = uni_head->next;
    flow->prev = uni_head;

    uni_head->next->prev = flow;
    uni_head->next = flow;

    ++uni_count;
}

// but remove from any point
void FlowCache::unlink_uni (Flow* flow)
{
    if ( !flow->next )
        return;

    --uni_count;

    flow->next->prev = flow->prev;
    flow->prev->next = flow->next;

    flow->next = flow->prev = nullptr;
}

Flow* FlowCache::get(Stream5Config* s5, const FlowKey* key, bool& init)
{
    time_t timestamp = packet_time();
    Flow* flow = (Flow*)hash_table->get(key, init);

    if ( !flow )
    {
        if ( !init )
            return NULL;

        if ( !prune_stale(timestamp, NULL) )
            if ( !prune_unis() )
                prune_excess(false, NULL);

        flow = (Flow*)hash_table->get(key, init);
        assert(flow);
    }
    if (flow && init)
    {
        flow->reset();
        flow->s5_config = s5;
        s5->handler->add_ref();
        link_uni(flow);
        flow->last_data_seen = timestamp;
#ifdef HA_ENABLE
        ha_reset(flow);
#endif
    }

    return flow;
}

int FlowCache::release(Flow* flow, const char*)
{
    if (!(flags & SESSION_CACHE_FLAG_PURGING))
    {
        ha_notify_deletion(flow);
    }
    flow->reset();
    flow->free_application_data();
    flow->s5_config->handler->rem_ref();

    return remove(flow);
}

int FlowCache::remove(Flow* flow)
{
    if ( flow->next )
        unlink_uni(flow);

    return hash_table->remove(flow->key);
}

uint32_t FlowCache::prune_stale(uint32_t thetime, Flow *save_me)
{
    Flow *flow;
    uint32_t pruned = 0;
    Active_Suspend();

    /* Pruning, look for flows that have time'd out */
    flow = (Flow*)hash_table->first();

    while ( flow )
    {
        if(flow == save_me)
            hash_table->touch();

        else if((flow->last_data_seen + timeoutAggressive) < thetime)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "pruning stale flow\n"););
            flow->s5_state.session_flags |= SSNFLAG_TIMEDOUT;
            release(flow, "stale/timeout");
            pruned++;
        }
        else
            break;

        if (pruned > cleanup_flows)
            break;

        flow = (Flow*)hash_table->first();
    }

    prunes += pruned;
    Active_Resume();
    return pruned;
}

uint32_t FlowCache::prune_unis()
{
    // we may have many or few unis; need to find reasonable ratio
    // FIXIT max_uni should be based on typical ratios seen in perfmon
    const uint32_t max_uni = (max_flows >> 2) + 1;

    Flow* curr = uni_tail->prev;
    uint32_t pruned = 0;
    Active_Suspend();

    while ( (uni_count > max_uni) && curr && (pruned < cleanup_flows) )
    {
        Flow* flow = curr;
        curr = curr->prev;

        if ( flow->was_blocked() )
            continue;

        release(flow, "unidirectional");
        ++pruned;
    }
    prunes += pruned;
    Active_Resume();
    return pruned;
}

uint32_t FlowCache::prune_excess(bool memCheck, Flow *save_me)
{
    /* Free up 'n' flows at a time until we get under the
     * memcap or free enough flows to be able to create
     * new ones.
     */
    const uint32_t max_cap = max_flows - cleanup_flows;
    uint32_t pruned = 0;
    Active_Suspend();

    while (
        (hash_table->get_count() > 1) &&
        ((!memCheck && ((hash_table->get_count() > max_cap) || !pruned)) ||
         (memCheck && tcp_memcap->at_max()) )) // FIXIT remove explicit dependence on tcp_memcap
    {
        unsigned int blocks = 0;
        Flow* flow = (Flow*)hash_table->first();

        for (unsigned i=0;i<cleanup_flows &&
             (hash_table->get_count() > blocks); i++)
        {
            if ( (flow != save_me) && (!memCheck || !flow->was_blocked()) )
            {
                flow->s5_state.session_flags |= SSNFLAG_PRUNED;
                release(flow, memCheck ? "memcap/check" : "memcap/stale");
                pruned++;
            }
            else
            {
                if ( flow->was_blocked() )
                    blocks++;

                if ( !hash_table->touch() )
                    break; // this flow is the only one left

                i--; /* Didn't clean this one */
            }
            flow = (Flow*)hash_table->first();
        }

        /* Nothing (or the one we're working with) in table, couldn't kill it */
        if (!memCheck && (pruned == 0))
            break;
    }
    prunes += pruned;
    Active_Resume();
    return pruned;
}

void FlowCache::timeout(uint32_t flowCount, time_t cur_time)
{
    uint32_t flowRetiredCount = 0, flowExaminedCount = 0;
    uint32_t flowMax = flowCount * 2;

    Flow* flow = (Flow*)hash_table->current();

    if ( !flow )
        flow = (Flow*)hash_table->first();

    while ( flow && flowRetiredCount < flowCount && flowExaminedCount < flowMax )
    {
        if ((time_t)(flow->last_data_seen + timeoutNominal) > cur_time)
           break;

        flowExaminedCount++;

        if ( ha_is_standby(flow) )
            continue;

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "retiring stale flow\n"););
        flow->s5_state.session_flags |= SSNFLAG_TIMEDOUT;
        release(flow, "stale/timeout");

        flowRetiredCount++;
        flow = (Flow*)hash_table->current();
    }
}

/* Remove all flows from the hash table. */
int FlowCache::purge()
{
    int retCount = 0;

    flags |= SESSION_CACHE_FLAG_PURGING;
    Flow* flow = (Flow*)hash_table->first();

    while ( flow )
    {
        flow->s5_state.session_flags |= SSNFLAG_PRUNED;
        release(flow, "purge whole cache");
        retCount++;
        flow = (Flow*)hash_table->first();
    }

    flags &= ~SESSION_CACHE_FLAG_PURGING;

    return retCount;
}

