//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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
// flow_data.h author Russ Combs <rucombs@cisco.com>

#ifndef FLOW_DATA_H
#define FLOW_DATA_H

#include <vector>

// FlowData is how inspectors maintain flow state
// use Flow::set/get_flow_data() to attach to a flow

#include <memory>

#include "framework/base_api.h"
#include "main/snort_types.h"

struct Plugin;

namespace snort
{
struct Packet;

class SO_PUBLIC FlowData
{
public:
    virtual ~FlowData();

    unsigned get_id() const
    { return id; }

    static unsigned create_flow_data_id();

    virtual void handle_expected(Packet*)
    { }
    virtual void handle_retransmit(Packet*)
    { }
    virtual void handle_eof(Packet*)
    { }

protected:
    FlowData(unsigned id);
    FlowData(unsigned id, const char* mod_name);

private:
    void init(unsigned);

    std::shared_ptr<Plugin> plugin = nullptr;
    static unsigned flow_data_id;
    unsigned id;
};

class SO_PUBLIC FlowDataStore
{
public:
    FlowDataStore() = default;
    ~FlowDataStore();

    void set(FlowData*);
    FlowData* get(unsigned) const;

    void erase(unsigned);
    void erase(FlowData*);
    void clear();

    bool empty() const;

    enum FlowDataHandlerType
    {
        HANDLER_RETRANSMIT,
        HANDLER_EOF,
    };

    void call_handlers(Packet*, FlowDataHandlerType) const;

    static constexpr unsigned FLOW_DATA_INCREMENTS = 7;

private:
    std::vector<FlowData*> flow_data;
};

}
#endif
