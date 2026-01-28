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

bool DumpFlows::execute(Analyzer&, void**)
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

bool DumpFlowsSummary::execute(Analyzer &, void **)
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
