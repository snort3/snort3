//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

// dump_flows.h author davis mcpherson <davmcphe@cisco.com>

#ifndef DUMP_FLOWS_H
#define DUMP_FLOWS_H

#include <array>
#include <fstream>
#include <string>
#include <vector>

#include "framework/decode_data.h"
#include "main/analyzer_command.h"
#include "sfip/sf_ip.h"

#include "dump_flows_descriptor.h"
#include "flow.h"

namespace snort
{
struct FlowKey;
}

class ZHash;

class DumpFlowsControl
{
public:
    ZHash* flow_table = nullptr;
    unsigned next = 0;
    unsigned proto_idx = 0;
    bool has_more_flows = false;
    std::vector<snort::Flow*> flow_cursor = {nullptr, nullptr, nullptr, nullptr, nullptr};
    std::string dump_file_name;
    std::fstream dump_stream;

};
class DumpFlowsBase : public snort::AnalyzerCommand
{
public:
    DumpFlowsBase(ControlConn*, DumpFlowsFilter*);
    virtual ~DumpFlowsBase() override;

    virtual void tinit(DumpFlowsControl&, ZHash*);

    const char* stringify() override = 0;

 protected:
    DumpFlowsFilter& dff;

    std::vector<LRUType>protocols = {LRUType::ICMP, LRUType::IP, LRUType::TCP, LRUType::UDP, LRUType::ALLOW_LIST};
    std::vector<DumpFlowsControl> dump_flows_control;
};

class DumpFlows : public DumpFlowsBase
{
public:

    DumpFlows(ControlConn*, DumpFlowsFilter*);
    ~DumpFlows() override = default;

    bool open_file(DumpFlowsControl& dfc);
    bool execute(Analyzer&, void**) override;
    const char* stringify() override
    { return "DumpFlows"; }

 protected:
    //dump_code is to track if the flow is dumped only once per dump_flow command.
    static uint8_t dump_code;
    std::string base_file_name;

    void dump_flows(DumpFlowsControl&, unsigned idx);
};

typedef std::array<unsigned, to_utype(PktType::MAX)> FlowsTypeSummary;
typedef std::array<unsigned, to_utype(snort::Flow::FlowState::ALLOW) + 1> FlowsStateSummary;

struct FlowsSummary
{
    FlowsTypeSummary type_summary{};
    FlowsStateSummary state_summary{};
};

class DumpFlowsSummary : public DumpFlowsBase
{
public:
    DumpFlowsSummary(ControlConn*, DumpFlowsFilter*);
    ~DumpFlowsSummary() override;

    bool execute(Analyzer&, void**) override;
    const char* stringify() override
    { return "DumpFlowsSummary"; }

    bool dump_flows_summary(DumpFlowsControl& dfc, unsigned idx, FlowsSummary& flows_summary);

protected:
    std::vector<FlowsSummary> flows_summaries;
};

#endif
