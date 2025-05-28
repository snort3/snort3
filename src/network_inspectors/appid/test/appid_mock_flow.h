//--------------------------------------------------------------------------
// Copyright (C) 2016-2025 Cisco and/or its affiliates. All rights reserved.
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

// appid_mock_flow.h author davis mcpherson <davmcphe@cisco.com>

#ifndef APPID_MOCK_FLOW_H
#define APPID_MOCK_FLOW_H

FlowData::FlowData(unsigned, Inspector*)
{
    handler = nullptr;
    id = 222;
}

FlowData::~FlowData() = default;

FlowData* mock_flow_data = nullptr;

typedef int32_t AppId;
Flow::~Flow() = default;
FlowDataStore::~FlowDataStore() = default;

class FakeFlow : public Flow
{
};

FlowData* FlowDataStore::get(unsigned) const
{
    return mock_flow_data;
}

void FlowDataStore::set(FlowData* fd)
{
    mock_flow_data = fd;
}

void FlowDataStore::erase(unsigned)
{
    mock_flow_data = nullptr;
}

bool FlowStash::get(const std::string &, StashGenericObject*&) const
{ return false; }

#endif

