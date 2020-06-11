//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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
// trace_api.cc author Oleksandr Serhiienko <oserhiie@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "trace_api.h"

#include "framework/packet_constraints.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "protocols/packet.h"

#include "trace_config.h"
#include "trace_log_base.h"

using namespace snort;

static THREAD_LOCAL TraceLogger* g_trace_logger = nullptr;
static THREAD_LOCAL PacketConstraints* g_packet_constraints = nullptr;
static THREAD_LOCAL uint8_t g_constraints_generation = 0;

static void update_constraints(PacketConstraints* new_cs)
{
    if (!g_packet_constraints and !new_cs)
        return;

    bool different_constraints = g_packet_constraints and new_cs and
        !(*g_packet_constraints == *new_cs);

    if ( !g_packet_constraints or !new_cs or different_constraints )
        g_constraints_generation++;

    g_packet_constraints = new_cs;
}

void TraceApi::thread_init(const TraceConfig* trace_config)
{
    if ( trace_config->logger_factory )
        g_trace_logger = trace_config->logger_factory->instantiate();

    update_constraints(trace_config->constraints);
    trace_config->setup_module_trace();
}

void TraceApi::thread_term()
{
    g_packet_constraints = nullptr;

    delete g_trace_logger;
    g_trace_logger = nullptr;
}

void TraceApi::thread_reinit(const TraceConfig* trace_config)
{
    update_constraints(trace_config->constraints);
    trace_config->setup_module_trace();
}

void TraceApi::log(const char* log_msg, const char* name,
    uint8_t log_level, const char* trace_option, const Packet* p)
{
    g_trace_logger->log(log_msg, name, log_level, trace_option, p);
}

void TraceApi::filter(const Packet& p)
{
    if ( !g_packet_constraints )
        p.filtering_state.set_matched(g_constraints_generation, true);
    else
    {
        const bool matched = p.flow
            ? g_packet_constraints->flow_match(*p.flow)
            : g_packet_constraints->packet_match(p);

        p.filtering_state.set_matched(g_constraints_generation, matched);
    }

    if ( p.flow )
        p.flow->filtering_state = p.filtering_state;
}

uint8_t TraceApi::get_constraints_generation()
{
    return g_constraints_generation;
}

