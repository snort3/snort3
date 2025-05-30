//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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

// flow_config.h author Russ Combs <rucombs@cisco.com>

#ifndef FLOW_CONFIG_H
#define FLOW_CONFIG_H

#include "framework/decode_data.h"

// configured by the stream module
struct FlowTypeConfig
{
    unsigned nominal_timeout = 0;
};

struct FlowCacheConfig
{
    unsigned max_flows = 0;
    unsigned pruning_timeout = 0;
    FlowTypeConfig proto[to_utype(PktType::MAX)];
    unsigned prune_flows = 0;
    bool allowlist_cache = false;
    bool move_to_allowlist_on_excess = false;
};

#endif

