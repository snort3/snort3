//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// expect_cache.h author Russ Combs <rucombs@cisco.com>

#ifndef EXPECT_CACHE_H
#define EXPECT_CACHE_H

// ExpectCache is used to track anticipated flows (like ftp data channels).
// when the flow is found, it updated with the given info.

#include "sfip/sfip_t.h"
#include "flow/flow.h"

struct Packet;

class ExpectCache
{
public:
    ExpectCache(uint32_t max);
    ~ExpectCache();

    int add_flow(
        const sfip_t *cliIP, uint16_t cliPort,
        const sfip_t *srvIP, uint16_t srvPort,
        PktType, char direction, FlowData*, int16_t appId = 0);

    bool is_expected(Packet*);
    char process_expected(Packet*, Flow*);
    char check(Packet*, Flow*);

    unsigned long get_expects() { return expects; }
    unsigned long get_realized() { return realized; }
    unsigned long get_prunes() { return prunes; }
    unsigned long get_overflows() { return overflows; }

private:
    void prune();

    struct ExpectNode* get_node(struct ExpectKey&, bool&);
    struct ExpectFlow* get_flow(ExpectNode*, uint32_t, int16_t);
    bool set_data(ExpectNode*, ExpectFlow*&, FlowData*);

private:
    class ZHash* hash_table;
    struct ExpectNode* nodes;
    struct ExpectFlow* pool, * list;
    sfip_t zeroed;

    unsigned long expects, realized;
    unsigned long prunes, overflows;
};

#endif

