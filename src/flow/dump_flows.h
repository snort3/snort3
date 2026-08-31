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
    bool execute(Analyzer&) override;
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

    bool execute(Analyzer&) override;
    const char* stringify() override
    { return "DumpFlowsSummary"; }

    bool dump_flows_summary(DumpFlowsControl& dfc, unsigned idx, FlowsSummary& flows_summary);

protected:
    std::vector<FlowsSummary> flows_summaries;
};

// Aggregated per-flow memory accounting. Reads only get_mem_usage()/
// get_peak_mem_usage() (both O(1)), so walking the cache is cheap.
struct FlowMemStats
{
    uint64_t count = 0;
    uint64_t total_bytes = 0;       // sum of current get_mem_usage()
    size_t cur_max = 0;             // largest current bytes
    size_t peak_max = 0;            // largest per-flow get_peak_mem_usage()

    // histogram upper bounds (bytes); the final bucket is the >= overflow
    static constexpr size_t HIST_BOUNDS[] =
    {
        1ull << 10, 4ull << 10, 16ull << 10, 64ull << 10, 256ull << 10,
        1ull << 20, 5ull << 20, 100ull << 20, 1ull << 30
    };
    static constexpr unsigned NUM_BUCKETS = std::size(HIST_BOUNDS) + 1;
    std::array<uint64_t, NUM_BUCKETS> hist {};

    void add(size_t cur, size_t peak)
    {
        ++count;
        total_bytes += cur;
        if ( cur > cur_max )
            cur_max = cur;
        if ( peak > peak_max )
            peak_max = peak;

        unsigned b = 0;
        while ( b < std::size(HIST_BOUNDS) and cur >= HIST_BOUNDS[b] )
            ++b;
        ++hist[b];
    }

    void merge(const FlowMemStats& o)
    {
        count += o.count;
        total_bytes += o.total_bytes;
        if ( o.cur_max > cur_max )
            cur_max = o.cur_max;
        if ( o.peak_max > peak_max )
            peak_max = o.peak_max;
        for ( unsigned i = 0; i < NUM_BUCKETS; ++i )
            hist[i] += o.hist[i];
    }
};

// A value copy of a flow's identity + memory; never holds a live Flow pointer,
// so it stays valid after the broadcast completes and flows may have been freed.
struct FlowMemRecord
{
    size_t peak = 0;                // sort key
    size_t cur = 0;                 // also printed
    snort::SfIp cli_ip;
    snort::SfIp srv_ip;
    uint16_t cli_port = 0;
    uint16_t srv_port = 0;
    PktType proto = PktType::NONE;
};

// Bounded min-heap (by peak) that retains the cap largest records seen.
class TopFlows
{
public:
    explicit TopFlows(unsigned n = 10) : cap(n) {}

    void set_cap(unsigned n) { cap = n; }
    void consider(const FlowMemRecord&);
    void merge(const TopFlows&);
    std::vector<FlowMemRecord> sorted_desc() const;

private:
    unsigned cap;
    std::vector<FlowMemRecord> heap;    // min-heap on .peak, size <= cap
};

struct FlowMemThreadResult
{
    std::array<FlowMemStats, to_utype(PktType::MAX)> per_proto {};
    FlowMemStats all {};
    TopFlows top;
};

class DumpFlowMemSummary : public DumpFlowsBase
{
public:
    DumpFlowMemSummary(ControlConn*, DumpFlowsFilter*, unsigned top_n);
    ~DumpFlowMemSummary() override;

    bool execute(Analyzer&) override;
    const char* stringify() override
    { return "DumpFlowMemSummary"; }

protected:
    unsigned top_n;
    std::vector<FlowMemThreadResult> results;

    void print(const FlowMemThreadResult& g);
};

#endif
