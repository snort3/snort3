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
// dump_flows.cc author davis mcpherson <davmcphe@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dump_flows.h"

#include <algorithm>
#include <filesystem>

#include "hash/zhash.h"
#include "log/messages.h"
#include "main/analyzer.h"
#include "stream/base/stream_module.h"
#include "stream/tcp/tcp_session.h"
#include "stream/tcp/tcp_trace.h"

#include "dump_flows_serializer.h"
#include "flow_key.h"

using namespace snort;

static const unsigned WDT_MASK = 7; // kick watchdog once for every 8 flows dumped
uint8_t DumpFlows::dump_code = 0;

DumpFlowsBase::DumpFlowsBase(ControlConn* conn, DumpFlowsFilter* dff)
    : snort::AnalyzerCommand(conn), dff(*dff)
{
    dump_flows_control.resize(ThreadConfig::get_instance_max());
}

DumpFlowsBase::~DumpFlowsBase()
{
    delete &dff;
}

void DumpFlowsBase::tinit(DumpFlowsControl& dfc, ZHash* flow_table)
{
    dfc.flow_table = flow_table;

    dfc.flow_cursor.resize(protocols.size(), nullptr);

    for (unsigned i = 0; i < protocols.size(); i++)
        dfc.flow_cursor[i] = static_cast<Flow*>(dfc.flow_table->get_walk_user_data(to_utype(protocols[i])));
}

DumpFlows::DumpFlows(ControlConn* conn, DumpFlowsFilter* filter)
    : DumpFlowsBase(conn, filter)
{
    if ( filter->proto_type != PktType::NONE )
    {
        protocols.clear();
        protocols.push_back(static_cast<LRUType>(filter->proto_type));
    }

    ++dump_code;
}

bool DumpFlows::open_file(DumpFlowsControl& dfc)
{
    std::string file_name = dff.file_name + std::to_string(get_relative_instance_number());

    if ( dff.binary_output )
    {
        file_name += ".bin";
        dfc.dump_stream.open(file_name, std::ios::binary | std::ios::out | std::ios::trunc);
    }
    else
        dfc.dump_stream.open(file_name, std::ios::out | std::ios::trunc);

    if ( dfc.dump_stream.rdstate() & std::fstream::failbit )
    {
        LogRespond(ctrlcon, "Dump flows failed to open %s\n", file_name.c_str());
        return false;
    }

    return true;
}

bool DumpFlows::execute(Analyzer&)
{
    if ( !flow_con )
        return true;

    unsigned int id = get_instance_id();
    DumpFlowsControl& dfc = dump_flows_control[id];

#ifdef REG_TEST
    if ( !dfc.next && -1 != dff.resume )
        Analyzer::get_local_analyzer()->resume(dff.resume);
#endif

    // on the first call to execute, do some initialization
    if ( !dfc.flow_table )
    {
        if ( open_file(dfc) )
            tinit(dfc, flow_con->get_flow_cache()->get_flow_table());
        else
            return true;
    
        dfc.next = 1;
    }

    dfc.has_more_flows = false;
    for( unsigned idx = 0; idx < protocols.size(); idx++ )
        dump_flows(dfc, idx);

    if ( !dfc.has_more_flows )
        dfc.dump_stream.close();

    return !dfc.has_more_flows;
}
void DumpFlows::dump_flows(DumpFlowsControl& dfc, unsigned idx)
{
    struct timeval now;
    packet_gettimeofday(&now);
    unsigned i = 0;

    while ( dfc.flow_cursor[idx] && i < dff.count )
    {
        if ( dfc.flow_cursor[idx]->dump_code != dump_code )
        {
            DumpFlowsSerializer dfs;
            SfIp server_ip, client_ip; 
            uint16_t server_port, client_port;
            const Flow& flow = *dfc.flow_cursor[idx];

            if ( flow.flags.key_is_reversed )
            {
                server_ip.set(flow.key->ip_h);
                server_port = flow.key->port_h;
                client_ip.set(flow.key->ip_l);
                client_port = flow.key->port_l;
            }
            else
            {
                server_ip.set(flow.key->ip_l);
                server_port = flow.key->port_l;
                client_ip.set(flow.key->ip_h);
                client_port = flow.key->port_h;
            }

            if ( dff.filter_none or dff.filter_flow(server_ip, client_ip, server_port, client_port) )
            {
                dfs.initialize(*dfc.flow_cursor[idx], now);

                if ( dff.binary_output )
                    dfs.write(dfc.dump_stream);
                else 
                    dfs.print(dfc.dump_stream);
            }
                        
            dfc.flow_cursor[idx]->dump_code = dump_code;
            ++i;
        }

        dfc.flow_cursor[idx] = static_cast<Flow *>(dfc.flow_table->get_next_walk_user_data(to_utype(protocols[idx])));
    }

    if ( dfc.flow_cursor[idx] )
        dfc.has_more_flows = true;
}

DumpFlowsSummary::DumpFlowsSummary(ControlConn* conn, DumpFlowsFilter* filter)
    : DumpFlowsBase(conn, filter)
{
    flows_summaries.resize(ThreadConfig::get_instance_max());
}

DumpFlowsSummary::~DumpFlowsSummary()
{
    FlowsTypeSummary type_summary{};
    FlowsStateSummary state_summary{};
    unsigned total_pkts = 0;

    for (const auto& flows_sum : flows_summaries)
    {
        for (unsigned i = 0; i < type_summary.size(); ++i)
        {
            type_summary[i] += flows_sum.type_summary[i];
            total_pkts += flows_sum.type_summary[i];
        }
        for (unsigned i = 0; i < state_summary.size(); ++i)
            state_summary[i] += flows_sum.state_summary[i];
    }

    LogRespond(ctrlcon, "Total: %u\n", total_pkts);
    for (unsigned i = 0; i < type_summary.size(); ++i)
    {
        PktType proto = static_cast<PktType>(i);

        switch ( proto )
        {
            case PktType::IP:
                LogRespond(ctrlcon, "IP: %u\n", type_summary[i]);
                break;

            case PktType::ICMP:
                LogRespond(ctrlcon, "ICMP: %u\n", type_summary[i]);
                break;

            case PktType::TCP:
                LogRespond(ctrlcon, "TCP: %u\n", type_summary[i]);
                break;

            case PktType::UDP:
                LogRespond(ctrlcon, "UDP: %u\n", type_summary[i]);
                break;

            default:
                break;
        }
    }

    unsigned pending = 0;
    for (unsigned i = 0; i < state_summary.size(); ++i)
    {
        snort::Flow::FlowState state = static_cast<snort::Flow::FlowState>(i);

        switch (state)
        {
            case snort::Flow::FlowState::ALLOW:
                LogRespond(ctrlcon, "Allowed: %u\n", state_summary[i]);
                break;

            case snort::Flow::FlowState::BLOCK:
                LogRespond(ctrlcon, "Blocked: %u\n", state_summary[i]);
                break; 

            default:
                pending += state_summary[i];
                break;
        }
    }
    LogRespond(ctrlcon, "Pending: %u\n", pending);
}

bool DumpFlowsSummary::execute(Analyzer &)
{
    if ( !flow_con )
        return true;

    unsigned id = get_instance_id();

    DumpFlowsControl& dfc = dump_flows_control[get_instance_id()];

    // on the first call to execute, do some initialization
    if ( !dfc.flow_table )
        tinit(dfc, flow_con->get_flow_cache()->get_flow_table());

    for( unsigned idx = 0; idx < protocols.size(); idx++ )
        dump_flows_summary(dfc, idx, flows_summaries[id]);

    return true;
}

bool DumpFlowsSummary::dump_flows_summary(DumpFlowsControl& dfc, unsigned idx, FlowsSummary& flows_summary)
{
    uint32_t processed_count = 0;

    while ( dfc.flow_cursor[idx] )
    {
        SfIp server_ip, client_ip; 
        uint16_t server_port, client_port;
        const Flow& flow = *dfc.flow_cursor[idx];
        if ( flow.flags.key_is_reversed )
        {
            server_ip.set(flow.key->ip_h);
            server_port = flow.key->port_h;
            client_ip.set(flow.key->ip_l);
            client_port = flow.key->port_l;
        }
        else
        {
            server_ip.set(flow.key->ip_l);
            server_port = flow.key->port_l;
            client_ip.set(flow.key->ip_h);
            client_port = flow.key->port_h;
        }

        if ( dff.filter_none or dff.filter_flow(server_ip, client_ip, server_port, client_port) )
        {
            flows_summary.type_summary[to_utype(dfc.flow_cursor[idx]->key->pkt_type)]++;
            flows_summary.state_summary[to_utype(dfc.flow_cursor[idx]->flow_state)]++;
        }

        dfc.flow_cursor[idx] = static_cast<Flow *>(dfc.flow_table->get_next_walk_user_data(to_utype(protocols[idx])));

        if ( (++processed_count & WDT_MASK) == 0 )
            ThreadConfig::preemptive_kick();
    }

    return true;
}

//--------------------------------------------------------------------------
// flow memory summary
//--------------------------------------------------------------------------

// min-heap comparator: parent <= children by peak, so heap.front() is the
// smallest of the retained set and is the first to be evicted.
static bool top_flow_greater(const FlowMemRecord& a, const FlowMemRecord& b)
{ return a.peak > b.peak; }

void TopFlows::consider(const FlowMemRecord& rec)
{
    if ( cap == 0 )
        return;

    if ( heap.size() < cap )
    {
        heap.push_back(rec);
        std::push_heap(heap.begin(), heap.end(), top_flow_greater);
    }
    else if ( rec.peak > heap.front().peak )
    {
        std::pop_heap(heap.begin(), heap.end(), top_flow_greater);
        heap.back() = rec;
        std::push_heap(heap.begin(), heap.end(), top_flow_greater);
    }
}

void TopFlows::merge(const TopFlows& o)
{
    for ( const auto& rec : o.heap )
        consider(rec);
}

std::vector<FlowMemRecord> TopFlows::sorted_desc() const
{
    std::vector<FlowMemRecord> out(heap);
    std::sort(out.begin(), out.end(),
        [](const FlowMemRecord& a, const FlowMemRecord& b) { return a.peak > b.peak; });
    return out;
}

static std::string human_bytes(size_t bytes)
{
    static const char* const units[] = { "B", "KB", "MB", "GB", "TB" };
    double val = static_cast<double>(bytes);
    unsigned u = 0;

    while ( val >= 1024.0 and u < (sizeof(units) / sizeof(units[0])) - 1 )
    {
        val /= 1024.0;
        ++u;
    }

    char buf[32];
    if ( u == 0 )
        snprintf(buf, sizeof(buf), "%uB", static_cast<unsigned>(bytes));
    else
        snprintf(buf, sizeof(buf), "%.1f%s", val, units[u]);

    return buf;
}

static const char* proto_name(PktType pt)
{
    switch ( pt )
    {
        case PktType::IP:   return "IP";
        case PktType::ICMP: return "ICMP";
        case PktType::TCP:  return "TCP";
        case PktType::UDP:  return "UDP";
        case PktType::USER: return "USER";
        case PktType::FILE: return "FILE";
        case PktType::PDU:  return "PDU";
        default:            return "OTHER";
    }
}

DumpFlowMemSummary::DumpFlowMemSummary(ControlConn* conn, DumpFlowsFilter* filter, unsigned n)
    : DumpFlowsBase(conn, filter), top_n(n)
{
    protocols = { LRUType::IP, LRUType::TCP, LRUType::UDP, LRUType::ICMP,
        LRUType::USER, LRUType::FILE, LRUType::PDU, LRUType::ALLOW_LIST };

    results.resize(ThreadConfig::get_instance_max());
}

static FlowMemRecord make_record(const Flow& flow, size_t cur, size_t peak)
{
    FlowMemRecord rec;
    rec.cur = cur;
    rec.peak = peak;
    rec.proto = flow.key->pkt_type;

    // Endpoint mapping must match DumpFlowsSerializer::initialize(): when the
    // key is not reversed, ip_l/port_l is the client and ip_h/port_h the server.
    if ( flow.flags.key_is_reversed )
    {
        rec.cli_ip.set(flow.key->ip_h);
        rec.cli_port = flow.key->port_h;
        rec.srv_ip.set(flow.key->ip_l);
        rec.srv_port = flow.key->port_l;
    }
    else
    {
        rec.cli_ip.set(flow.key->ip_l);
        rec.cli_port = flow.key->port_l;
        rec.srv_ip.set(flow.key->ip_h);
        rec.srv_port = flow.key->port_h;
    }

    return rec;
}

bool DumpFlowMemSummary::execute(Analyzer&)
{
    if ( !flow_con )
        return true;

    unsigned id = get_instance_id();
    DumpFlowsControl& dfc = dump_flows_control[id];

    if ( !dfc.flow_table )
        tinit(dfc, flow_con->get_flow_cache()->get_flow_table());

    FlowMemThreadResult& res = results[id];
    res.top.set_cap(top_n);
    uint32_t processed_count = 0;

    for ( unsigned idx = 0; idx < protocols.size(); idx++ )
    {
        while ( dfc.flow_cursor[idx] )
        {
            const Flow& flow = *dfc.flow_cursor[idx];
            const size_t cur = flow.get_mem_usage();
            const size_t peak = flow.get_peak_mem_usage();
            const auto pt = to_utype(flow.key->pkt_type);

            res.per_proto[pt].add(cur, peak);
            res.all.add(cur, peak);
            res.top.consider(make_record(flow, cur, peak));

            dfc.flow_cursor[idx] = static_cast<Flow*>(
                dfc.flow_table->get_next_walk_user_data(to_utype(protocols[idx])));

            if ( (++processed_count & WDT_MASK) == 0 )
                ThreadConfig::preemptive_kick();
        }
    }

    return true;
}

void DumpFlowMemSummary::print(const FlowMemThreadResult& g)
{
    auto print_stats = [this](const char* label, const FlowMemStats& s)
    {
        const size_t avg = s.count ? s.total_bytes / s.count : 0;
        LogRespond(ctrlcon,
            "  %-5s count %lu  total %s  avg %s  cur_max %s  peak_max %s\n",
            label, static_cast<unsigned long>(s.count),
            human_bytes(s.total_bytes).c_str(), human_bytes(avg).c_str(),
            human_bytes(s.cur_max).c_str(), human_bytes(s.peak_max).c_str());
    };

    LogRespond(ctrlcon, "flow memory summary (live flows)\n");

    for ( unsigned p = 0; p < g.per_proto.size(); ++p )
    {
        if ( g.per_proto[p].count )
            print_stats(proto_name(static_cast<PktType>(p)), g.per_proto[p]);
    }
    print_stats("ALL", g.all);

    // histogram of current bytes
    static const char* const labels[] =
    { "<1K", "<4K", "<16K", "<64K", "<256K", "<1M", "<5M", "<100M", "<1G", ">=1G" };

    std::string hist = "histogram (current bytes):\n ";
    for ( unsigned b = 0; b < FlowMemStats::NUM_BUCKETS; ++b )
    {
        hist += " ";
        hist += labels[b];
        hist += ":";
        hist += std::to_string(g.all.hist[b]);
    }
    LogRespond(ctrlcon, "%s\n", hist.c_str());

    // top-N by peak
    const auto top = g.top.sorted_desc();
    LogRespond(ctrlcon, "top %u flows by peak memory:\n",
        static_cast<unsigned>(top.size()));

    for ( const auto& rec : top )
    {
        SfIpString cli_str, srv_str;
        rec.cli_ip.ntop(cli_str);
        rec.srv_ip.ntop(srv_str);

        LogRespond(ctrlcon, "  peak %s  cur %s  %s:%u -> %s:%u  %s\n",
            human_bytes(rec.peak).c_str(), human_bytes(rec.cur).c_str(),
            cli_str, rec.cli_port, srv_str, rec.srv_port,
            proto_name(rec.proto));
    }
}

DumpFlowMemSummary::~DumpFlowMemSummary()
{
    FlowMemThreadResult g;
    g.top.set_cap(top_n);

    for ( const auto& r : results )
    {
        for ( unsigned p = 0; p < r.per_proto.size(); ++p )
            g.per_proto[p].merge(r.per_proto[p]);
        g.all.merge(r.all);
        g.top.merge(r.top);
    }

    print(g);
}
