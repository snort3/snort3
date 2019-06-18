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

void RnaIcmpEventHandler::handle(snort::DataEvent&, snort::Flow*)
{
    Profile profile(rna_perf_stats);

    ++rna_stats.icmp;
}

void RnaIpEventHandler::handle(snort::DataEvent&, snort::Flow*)
{
    Profile profile(rna_perf_stats);

    ++rna_stats.ip;
}

void RnaUdpEventHandler::handle(snort::DataEvent&, snort::Flow*)
{
    Profile profile(rna_perf_stats);

    ++rna_stats.udp;
}

void RnaTcpSynEventHandler::handle(snort::DataEvent&, snort::Flow*)
{
    Profile profile(rna_perf_stats);

    ++rna_stats.tcp_syn;
}

void RnaTcpSynAckEventHandler::handle(snort::DataEvent&, snort::Flow*)
{
    Profile profile(rna_perf_stats);

    ++rna_stats.tcp_syn_ack;
}

void RnaTcpMidstreamEventHandler::handle(snort::DataEvent&, snort::Flow*)
{
    Profile profile(rna_perf_stats);

    ++rna_stats.tcp_midstream;
}
