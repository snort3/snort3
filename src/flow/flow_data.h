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
// flow_data.h author Russ Combs <rucombs@cisco.com>

#ifndef FLOW_DATA_H
#define FLOW_DATA_H

// FlowData is how inspectors maintain flow state
// use Flow::set/get_flow_data() to attach to a flow

#include "main/snort_types.h"

namespace snort
{
class Inspector;
struct Packet;

class SO_PUBLIC FlowData
{
public:
    virtual ~FlowData();

    unsigned get_id()
    { return id; }

    static unsigned create_flow_data_id()
    { return ++flow_data_id; }

    Inspector* get_handler() { return handler; }

    virtual void handle_expected(Packet*) { }
    virtual void handle_retransmit(Packet*) { }
    virtual void handle_eof(Packet*) { }

protected:
    FlowData(unsigned u, Inspector* = nullptr);

public:  // FIXIT-L privatize
    FlowData* next;
    FlowData* prev;

private:
    static unsigned flow_data_id;
    Inspector* handler;
    unsigned id;
};

// The flow data created from SO rules must use RuleFlowData
// to support reload
class SO_PUBLIC RuleFlowData : public FlowData
{
protected:
    RuleFlowData(unsigned u);
public:
    ~RuleFlowData() override = default;
};

}
#endif
