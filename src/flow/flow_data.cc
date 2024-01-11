//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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
// flow_data.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow_data.h"

#include <cassert>

#include "framework/inspector.h"
#include "main/snort_config.h"
#include "managers/so_manager.h"

using namespace snort;

unsigned FlowData::flow_data_id = 0;

FlowData::FlowData(unsigned u, Inspector* ph)
{
    assert(u > 0);
    id = u;
    handler = ph;
    prev = next = nullptr;
    if ( handler )
        handler->add_ref();
}

FlowData::~FlowData()
{
    if ( handler )
        handler->rem_ref();
}

RuleFlowData::RuleFlowData(unsigned u) :
    FlowData(u, SnortConfig::get_conf()->so_rules->proxy)
{ }

