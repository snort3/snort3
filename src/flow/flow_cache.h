//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

#ifndef FLOW_CACHE_H
#define FLOW_CACHE_H

#include "flow/flow_key.h"
#include "stream/stream.h"

class FlowCache
{
public:
    FlowCache(
        int max_flows,
        uint32_t flow_timeout_min,
        uint32_t flow_timeout_max,
        uint32_t cleanup_flows,
        uint32_t cleanup_percent);

    ~FlowCache();

    void push(Flow*);

    Flow* find(const FlowKey*);
    Flow* get(const FlowKey*);

    int release(Flow*, const char* reason);

    uint32_t prune_unis();
    uint32_t prune_stale(uint32_t thetime, Flow* save_me);
    uint32_t prune_excess(bool memCheck, Flow* save_me);
    void timeout(uint32_t flowCount, time_t cur_time);

    int purge();
    int get_count();

    uint32_t get_max_flows() { return max_flows; }
    uint32_t get_prunes() { return prunes; }
    void reset_prunes() { prunes = 0; }

    void unlink_uni(Flow*);

private:
    void link_uni(Flow*);
    int remove(Flow*);

private:
    uint32_t timeoutAggressive;
    uint32_t timeoutNominal;
    uint32_t max_flows;
    uint32_t cleanup_flows;
    uint32_t prunes;
    uint32_t uni_count;
    uint32_t flags;

    class ZHash* hash_table;
    Flow* uni_head, * uni_tail;
};

#endif

