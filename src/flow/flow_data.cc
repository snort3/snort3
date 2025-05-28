//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <algorithm>
#include <cassert>

#include "framework/inspector.h"
#include "main/snort_config.h"
#include "managers/so_manager.h"

using namespace snort;

unsigned FlowData::flow_data_id = 0;

FlowDataStore::~FlowDataStore()
{ clear(); }

void FlowDataStore::set(FlowData* fd)
{
    assert(fd);
    unsigned id = fd->get_id();
    if (flow_data.size() == flow_data.capacity())
        flow_data.reserve(flow_data.size() + FLOW_DATA_INCREMENTS);
    const auto lower = std::lower_bound(flow_data.begin(), flow_data.end(), id,
        [](const FlowData* the_fd, unsigned id)
        { return the_fd->get_id() < id; });
    if (lower == flow_data.end())
        flow_data.emplace_back(fd);
    else
    {
        FlowData* lower_fd = *lower;
        if (lower_fd->get_id() == id)
        {
            delete lower_fd;
            *lower = fd;
        }
        else
            flow_data.emplace(lower, fd);
    }
}

void FlowDataStore::erase(unsigned id)
{
    const auto lower = std::lower_bound(flow_data.begin(), flow_data.end(), id,
        [](const FlowData* the_fd, unsigned id)
        { return the_fd->get_id() < id; });
    if (lower != flow_data.end() && (*lower)->get_id() == id)
    {
        FlowData* lower_fd = *lower;
        flow_data.erase(lower);
        delete lower_fd;
    }
}

void FlowDataStore::clear()
{
    // Cannot use unique_ptr because resize and pop_back leave the flow_data element in
    // the vector. This can lead to crashes if the vector is used during the flow data destruction.
    while (!flow_data.empty())
    {
        FlowData* fd = flow_data.back();
        flow_data.pop_back();
        delete fd;
    }
}

FlowData* FlowDataStore::get(unsigned id) const
{
    const auto lower = std::lower_bound(flow_data.begin(), flow_data.end(), id,
        [](const FlowData* the_fd, unsigned id)
        { return the_fd->get_id() < id; });
    if (lower == flow_data.end())
        return nullptr;
    FlowData* lower_fd = *lower;
    return (lower_fd->get_id() == id) ? lower_fd : nullptr;
}

bool FlowDataStore::empty() const
{ return flow_data.empty(); }

void FlowDataStore::call_handlers(Packet* p, FlowDataHandlerType handler_type) const
{
    // handle_eof modifies flow_data, so we must make a temporary vector to be walked
    std::vector<FlowData*> fd_ptrs;
    fd_ptrs.reserve(flow_data.size());
    for (FlowData* fd : flow_data)
    {
        assert(fd);
        fd_ptrs.push_back(fd);
    }

    for (FlowData* fd : fd_ptrs)
    {
        switch (handler_type)
        {
            case HANDLER_RETRANSMIT:
                fd->handle_retransmit(p);
                break;
            case HANDLER_EOF:
                fd->handle_eof(p);
                break;
            default:
                assert(!"Invalid handler type");
        }
    }
}

FlowData::FlowData(unsigned u, Inspector* ph)
{
    assert(u > 0);
    id = u;
    handler = ph;
    if ( handler )
        handler->add_ref();
}

FlowData::~FlowData()
{
    if ( handler )
        handler->rem_ref();
}

void FlowData::set_handler(Inspector* h)
{
    if (handler != h)
    {
        if (handler)
            handler->rem_ref();
        handler = h;
        if (handler)
            handler->add_ref();
    }
}

RuleFlowData::RuleFlowData(unsigned u) :
    FlowData(u, SnortConfig::get_conf()->so_rules->proxy)
{ }
