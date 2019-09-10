//--------------------------------------------------------------------------
// Copyright (C) 2019-2019 Cisco and/or its affiliates. All rights reserved.
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

// rna_event_handler.cc author Masud Hasan <mashasan@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rna_event_handler.h"

using namespace snort;

void RnaIcmpBidirectionalEventHandler::handle(DataEvent& event, Flow*)
{
    Profile profile(rna_perf_stats);
    ++rna_stats.icmp_bidirectional;
    pnd.analyze_flow_icmp(event.get_packet());
}

void RnaIcmpNewFlowEventHandler::handle(DataEvent& event, Flow*)
{
    Profile profile(rna_perf_stats);
    ++rna_stats.icmp_new;
    pnd.analyze_flow_icmp(event.get_packet());
}

void RnaIpBidirectionalEventHandler::handle(DataEvent& event, Flow*)
{
    Profile profile(rna_perf_stats);
    ++rna_stats.ip_bidirectional;
    pnd.analyze_flow_ip(event.get_packet());
}

void RnaIpNewFlowEventHandler::handle(DataEvent& event, Flow*)
{
    Profile profile(rna_perf_stats);
    ++rna_stats.ip_new;
    pnd.analyze_flow_ip(event.get_packet());
}

void RnaTcpSynEventHandler::handle(DataEvent& event, Flow*)
{
    Profile profile(rna_perf_stats);
    ++rna_stats.tcp_syn;
    pnd.analyze_flow_tcp(event.get_packet(), TcpPacketType::SYN);
}

void RnaTcpSynAckEventHandler::handle(DataEvent& event, Flow*)
{
    Profile profile(rna_perf_stats);
    ++rna_stats.tcp_syn_ack;
    pnd.analyze_flow_tcp(event.get_packet(), TcpPacketType::SYN_ACK);
}

void RnaTcpMidstreamEventHandler::handle(DataEvent& event, Flow*)
{
    Profile profile(rna_perf_stats);
    ++rna_stats.tcp_midstream;
    pnd.analyze_flow_tcp(event.get_packet(), TcpPacketType::MIDSTREAM);
}

void RnaUdpBidirectionalEventHandler::handle(DataEvent& event, Flow*)
{
    Profile profile(rna_perf_stats);
    ++rna_stats.udp_bidirectional;
    pnd.analyze_flow_udp(event.get_packet());
}

void RnaUdpNewFlowEventHandler::handle(DataEvent& event, Flow*)
{
    Profile profile(rna_perf_stats);
    ++rna_stats.udp_new;
    pnd.analyze_flow_udp(event.get_packet());
}

void RnaIdleEventHandler::handle(DataEvent& event, Flow*)
{
    UNUSED(event);
    Profile profile(rna_perf_stats);
    ++rna_stats.change_host_update;
    pnd.generate_change_host_update();
}
