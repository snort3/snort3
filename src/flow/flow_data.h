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
class Flow;
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

    virtual size_t size_of() const
    { return sizeof(FlowData); }

protected:
    FlowData(unsigned id);
    FlowData(unsigned id, const char* mod_name);

    // Set by FlowDataStore on attach. Subclasses use it only to push their
    // own dynamic allocations via add_mem()/sub_mem().
    //
    // Unlike FlowStash/FlowDataStore, stays nullable and keeps set_flow(): a
    // FlowData can predate its flow (e.g. FtpDataFlowData in pp_ftp.cc, held by
    // ExpectFlow until process_expected() attaches it, or deleted if the flow
    // never shows up), so callers must null check it.
    //
    // named owner_flow (not flow) to avoid -Wshadow-field with subclasses that keep their own Flow* flow.
    void set_flow(Flow* f) { owner_flow = f; }
    Flow* owner_flow = nullptr;

private:
    friend class FlowDataStore;
    void init(unsigned);

    std::shared_ptr<Plugin> plugin = nullptr;
    static unsigned flow_data_id;
    unsigned id;
};

#define FLOW_DATA_SIZE_OF(C) \
    size_t size_of() const override { return sizeof(C); }
#define FLOW_DATA_SIZE_OF_EXTRA(C, EXTRA) \
    size_t size_of() const override { return sizeof(C) + (EXTRA); }

class SO_PUBLIC FlowDataStore
{
public:
    // owner passed at construction (a store only exists as a Flow member) so
    // accounting paths need no null checks
    explicit FlowDataStore(Flow* f) : owner_flow(f) { }
    ~FlowDataStore();

    void set(FlowData*);
    FlowData* get(unsigned) const;

    void erase(unsigned);
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
    Flow* const owner_flow;
};

}
#endif
