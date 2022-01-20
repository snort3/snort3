//--------------------------------------------------------------------------
// Copyright (C) 2020-2022 Cisco and/or its affiliates. All rights reserved.
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
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "protocols/packet.h"

#include "trace_config.h"
#include "trace_logger.h"

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

static inline void set_logger_options(const TraceConfig* trace_config)
{
    if ( g_trace_logger )
    {
        g_trace_logger->set_ntuple(trace_config->ntuple);
        g_trace_logger->set_timestamp(trace_config->timestamp);
    }
}

void TraceApi::thread_init(const TraceConfig* trace_config)
{
    if ( trace_config->logger_factory )
        g_trace_logger = trace_config->logger_factory->instantiate();

    set_logger_options(trace_config);
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
    set_logger_options(trace_config);
    update_constraints(trace_config->constraints);
    trace_config->setup_module_trace();
}

bool TraceApi::override_logger_factory(SnortConfig* sc, TraceLoggerFactory* factory)
{
    if ( !sc or !sc->trace_config or !factory )
        return false;

    delete sc->trace_config->logger_factory;
    sc->trace_config->logger_factory = factory;

    if ( !Snort::is_reloading() )
    {
        delete g_trace_logger;
        g_trace_logger = sc->trace_config->logger_factory->instantiate();
    }

    return true;
}

void TraceApi::log(const char* log_msg, const char* name,
    uint8_t log_level, const char* trace_option, const Packet* p)
{
    g_trace_logger->log(log_msg, name, log_level, trace_option, p);
}

void TraceApi::filter(const Packet& p)
{

    if ( p.pkth->flags & DAQ_PKT_FLAG_DEBUG_ENABLED )
        p.filtering_state.set_matched(g_constraints_generation, true);
    else
    {
        bool matched;
        if ( !g_packet_constraints )
            matched = true;
        else
        {
            matched = p.flow
            ? g_packet_constraints->flow_match(*p.flow)
            : g_packet_constraints->packet_match(p);
        }
        p.filtering_state.set_matched(g_constraints_generation, matched);
    }

    if ( p.flow )
        p.flow->filtering_state = p.filtering_state;
}

uint8_t TraceApi::get_constraints_generation()
{
    return g_constraints_generation;
}

