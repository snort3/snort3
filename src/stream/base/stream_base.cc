/****************************************************************************
 *
 * Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

#include "stream/stream.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "stream_module.h"
#include "snort.h"
#include "snort_debug.h"
#include "framework/inspector.h"
#include "framework/plug_data.h"
#include "framework/share.h"
#include "managers/inspector_manager.h"
#include "managers/module_manager.h"
#include "flow/flow_control.h"
#include "stream/stream_api.h"
#include "profiler.h"

//-------------------------------------------------------------------------
// globals
//-------------------------------------------------------------------------

#ifdef PERF_PROFILING
static THREAD_LOCAL PreprocStats s5PerfStats;

static PreprocStats* s5_get_profile(const char* key)
{
    if ( !strcmp(key, MOD_NAME) )
        return &s5PerfStats;

    return nullptr;
}
#endif

THREAD_LOCAL FlowControl* flow_con = nullptr;

const char* session_pegs[] =
{
    "sessions",
    "prunes",
    "timeouts",
    "created",
    "released",
    "discards",
    "events"
};

const unsigned session_peg_count = array_size(session_pegs);

struct BaseStats
{
    PegCount tcp;
    PegCount udp;
    PegCount icmp;
    PegCount ip;
};

static BaseStats g_stats;
static THREAD_LOCAL BaseStats t_stats;

static const char* base_pegs[] =
{
    "tcp flows",
    "udp flows",
    "icmp flows",
    "ip flows"
};

//-------------------------------------------------------------------------
// runtime support
//-------------------------------------------------------------------------

static inline bool is_eligible(Packet* p)
{
    if ( p->error_flags & PKT_ERR_CKSUM_IP )
        return false;

    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return false;

    if ( !IPH_IS_VALID(p) )
        return false;

    return true;
}

Stream5GlobalConfig::Stream5GlobalConfig()
{
    flags = 0;
    prune_log_max = 1048576;
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class StreamBase : public Inspector
{
public:
    StreamBase(const StreamConfig*);

    void show(SnortConfig*);

    void pinit();
    void pterm();

    void eval(Packet*);

public:
    const StreamConfig* config;
};

StreamBase::StreamBase(const StreamConfig* c)
{
    config = c;
}

void StreamBase::pinit()
{
    assert(!flow_con);
    flow_con = new FlowControl();
    InspectSsnFunc f;

    if ( config->tcp_cfg.max_sessions )
    {
        f = InspectorManager::get_session("stream_tcp");
        flow_con->init_tcp(config->tcp_cfg, f);
    }
    if ( config->udp_cfg.max_sessions )
    {
        f = InspectorManager::get_session("stream_udp");
        flow_con->init_udp(config->udp_cfg, f);
    }
    if ( config->ip_cfg.max_sessions )
    {
        f = InspectorManager::get_session("stream_ip");
        flow_con->init_ip(config->ip_cfg, f);
    }
    if ( config->icmp_cfg.max_sessions )
    {
        f = InspectorManager::get_session("stream_icmp");
        flow_con->init_icmp(config->icmp_cfg, f);
    }
    if ( config->tcp_cfg.max_sessions || config->udp_cfg.max_sessions )
    {
        flow_con->init_exp(config->tcp_cfg, config->udp_cfg);
    }
}

void StreamBase::pterm()
{
    flow_con->purge_flows(IPPROTO_TCP);
    flow_con->purge_flows(IPPROTO_UDP);
    flow_con->purge_flows(IPPROTO_ICMP);
    flow_con->purge_flows(IPPROTO_IP);

    delete flow_con;
    flow_con = nullptr;
}

void StreamBase::show(SnortConfig*)
{
    // FIXIT SSN print 
    //Stream5PrintGlobalConfig(&config);
}

void StreamBase::eval(Packet *p)
{
    PROFILE_VARS;

    if ( !is_eligible(p) )
        return;

    PREPROC_PROFILE_START(s5PerfStats);

    switch ( GET_IPH_PROTO(p) )
    {
    case IPPROTO_TCP:
        if ( p->tcph )
            flow_con->process_tcp(p);
        break;

    case IPPROTO_UDP:
        if ( p->frag_flag )
            flow_con->process_ip(p);

        if ( p->udph )
            flow_con->process_udp(p);
        break;

    case IPPROTO_ICMP:
        if ( p->icmph )
            flow_con->process_icmp(p);
        break;

    case IPPROTO_IP:
        if ( p->iph )
            flow_con->process_ip(p);
        break;
    }

    PREPROC_PROFILE_END(s5PerfStats);
}

#if 0
    // FIXIT add method to get exp cache?
    LogMessage("            Expected Flows\n");
    LogMessage("                  Expected: %lu\n", exp_cache->get_expects());
    LogMessage("                  Realized: %lu\n", exp_cache->get_realized());
    LogMessage("                    Pruned: %lu\n", exp_cache->get_prunes());
    LogMessage("                 Overflows: %lu\n", exp_cache->get_overflows());
#endif

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new StreamModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* base_ctor(Module* m)
{
    StreamModule* mod = (StreamModule*)m;
    return new StreamBase(mod->get_data());
}

static void base_dtor(Inspector* p)
{
    delete p;
}

static void base_init()
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile(
        MOD_NAME, &s5PerfStats, 0, &totalPerfStats, s5_get_profile);
#endif
}

void base_sum()
{   
    t_stats.tcp = flow_con->get_flow_count(IPPROTO_TCP);
    t_stats.udp = flow_con->get_flow_count(IPPROTO_UDP);
    t_stats.icmp = flow_con->get_flow_count(IPPROTO_ICMP);
    t_stats.ip = flow_con->get_flow_count(IPPROTO_IP);

    sum_stats((PegCount*)&g_stats, (PegCount*)&t_stats,
        array_size(base_pegs));
}   
    
void base_stats()
{   
    show_stats((PegCount*)&g_stats, base_pegs, array_size(base_pegs),
        MOD_NAME);
}

void base_reset()
{
    flow_con->clear_flow_counts();
    memset(&t_stats, 0, sizeof(t_stats));
}

static const InspectApi base_api =
{
    {
        PT_INSPECTOR,
        MOD_NAME,
        INSAPI_PLUGIN_V0,
        0,
        mod_ctor,
        mod_dtor
    },
    IT_STREAM,
    PROTO_BIT__IP,
    base_init,
    nullptr, // term
    base_ctor,
    base_dtor,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // ssn
    base_sum,
    base_stats,
    base_reset
};

const BaseApi* nin_stream_base = &base_api.base;

