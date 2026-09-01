//--------------------------------------------------------------------------
// Copyright (C) 2026-2026 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
//--------------------------------------------------------------------------
// survivor_flow_data.cc author Bhumika Sachdeva <bsachdev@cisco.com>

// framework-owned SurvivorFlowData pin.
// split from reload_survivor_subscriptions.cc for standalone unit-test compile

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "reload_survivor_subscriptions_impl.h"

#include <algorithm>
#include <cassert>

#include "flow/flow.h"
#include "framework/inspector.h"
#include "managers/inspector_manager.h"

namespace snort
{

unsigned SurvivorFlowData::flow_data_id = FlowData::create_flow_data_id();

SurvivorFlowData::SurvivorFlowData(Inspector* pin)
    : FlowData(flow_data_id)
{
    assert(pin);
    pinned.push_back(pin);
    pin->add_ref();
}

SurvivorFlowData::~SurvivorFlowData()
{
    for ( auto* pin : pinned )
    {
        pin->rem_ref();
        InspectorManager::thread_drain_pending_tterm_if_pending(pin);
    }
}

void SurvivorFlowData::add_pin(Inspector* pin)
{
    assert(pin);

    if ( std::find(pinned.begin(), pinned.end(), pin) != pinned.end() )
        return;

    pinned.push_back(pin);
    pin->add_ref();
}

void Flow::pin_survivor_flow_data(Inspector& outgoing)
{
    if ( !InspectorManager::is_pending_tterm(&outgoing) )
        return;

    // idempotent per distinct inspector -- a flow rebinding through
    // multiple removed inspectors (A -> B -> C) pins each one
    auto* existing = static_cast<SurvivorFlowData*>(
        get_flow_data(SurvivorFlowData::get_flow_data_id()));

    if ( existing )
    {
        existing->add_pin(&outgoing);
        return;
    }

    set_flow_data(new SurvivorFlowData(&outgoing));
}

}
