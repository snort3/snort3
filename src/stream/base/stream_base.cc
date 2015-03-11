//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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
#include "managers/inspector_manager.h"
#include "managers/module_manager.h"
#include "flow/flow_control.h"
#include "stream/stream_api.h"
#include "profiler.h"

//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------

THREAD_LOCAL ProfileStats s5PerfStats;
THREAD_LOCAL FlowControl* flow_con = nullptr;

struct BaseStats
{
    PegCount tcp_flows;
    PegCount tcp_prunes;

    PegCount udp_flows;
    PegCount udp_prunes;

    PegCount icmp_flows;
    PegCount icmp_prunes;

    PegCount ip_flows;
    PegCount ip_prunes;
};

static BaseStats g_stats;
static THREAD_LOCAL BaseStats t_stats;

const PegInfo base_pegs[] =
{
    { "tcp flows", "total tcp sessions" },
    { "tcp prunes", "tcp sessions pruned" },
    { "udp flows", "total udp sessions" },
    { "udp prunes", "udp sessions pruned" },
    { "icmp flows", "total icmp sessions" },
    { "icmp prunes", "icmp sessions pruned" },
    { "ip flows", "total ip sessions" },
    { "ip prunes", "ip sessions pruned" },
    { nullptr, nullptr }
};

void base_sum()
{
    if ( !flow_con )
        return;

    t_stats.tcp_flows = flow_con->get_flows(IPPROTO_TCP);
    t_stats.tcp_prunes = flow_con->get_prunes(IPPROTO_TCP);

    t_stats.udp_flows = flow_con->get_flows(IPPROTO_UDP);
    t_stats.udp_prunes = flow_con->get_prunes(IPPROTO_UDP);

    t_stats.icmp_flows = flow_con->get_flows(IPPROTO_ICMP);
    t_stats.icmp_prunes = flow_con->get_prunes(IPPROTO_ICMP);

    t_stats.ip_flows = flow_con->get_flows(IPPROTO_IP);
    t_stats.ip_prunes = flow_con->get_prunes(IPPROTO_IP);

    sum_stats((PegCount*)&g_stats, (PegCount*)&t_stats,
        array_size(base_pegs)-1);
}

void base_stats()
{
    show_stats((PegCount*)&g_stats, base_pegs, array_size(base_pegs)-1, MOD_NAME);
}

void base_reset()
{
    if ( flow_con )
        flow_con->clear_counts();

    memset(&t_stats, 0, sizeof(t_stats));
}

//-------------------------------------------------------------------------
// runtime support
//-------------------------------------------------------------------------

static inline bool is_eligible(Packet* p)
{
    // FIXIT-M  --  extra check??   bad checksums should be removed
    //              in detect.c snort_inspect()
    if ( p->ptrs.decode_flags & DECODE_ERR_CKSUM_IP )
        return false;

    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return false;

    if ( !p->ptrs.ip_api.is_valid() )
        return false;

    return true;
}

StreamGlobalConfig::StreamGlobalConfig()
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
    StreamBase(const StreamModuleConfig*);

    void show(SnortConfig*) override;

    void tinit() override;
    void tterm() override;

    void eval(Packet*) override;

public:
    const StreamModuleConfig* config;
};

StreamBase::StreamBase(const StreamModuleConfig* c)
{
    config = c;
}

void StreamBase::tinit()
{
    assert(!flow_con);
    flow_con = new FlowControl;
    InspectSsnFunc f;

    if ( config->tcp_cfg.max_sessions )
    {
        if ( (f = InspectorManager::get_session((uint16_t)PktType::TCP)) )
            flow_con->init_tcp(config->tcp_cfg, f);
    }
    if ( config->udp_cfg.max_sessions )
    {
        if ( (f = InspectorManager::get_session((uint16_t)PktType::UDP)) )
            flow_con->init_udp(config->udp_cfg, f);
    }
    if ( config->ip_cfg.max_sessions )
    {
        if ( (f = InspectorManager::get_session((uint16_t)PktType::IP)) )
            flow_con->init_ip(config->ip_cfg, f);
    }
    if ( config->icmp_cfg.max_sessions )
    {
        if ( (f = InspectorManager::get_session((uint16_t)PktType::ICMP)) )
            flow_con->init_icmp(config->icmp_cfg, f);
    }
    if ( config->tcp_cfg.max_sessions || config->udp_cfg.max_sessions )
    {
        flow_con->init_exp(config->tcp_cfg, config->udp_cfg);
    }
}

void StreamBase::tterm()
{
    flow_con->purge_flows(IPPROTO_TCP);
    flow_con->purge_flows(IPPROTO_UDP);
    flow_con->purge_flows(IPPROTO_ICMP);
    flow_con->purge_flows(IPPROTO_IP);
}

void StreamBase::show(SnortConfig*)
{
    // FIXIT-L SSN print
    //StreamPrintGlobalConfig(&config);
}

void StreamBase::eval(Packet* p)
{
    PROFILE_VARS;

    if ( !is_eligible(p) )
        return;

    MODULE_PROFILE_START(s5PerfStats);

    switch ( p->type() )
    {
    case PktType::TCP:
        if ( p->ptrs.tcph )
            flow_con->process_tcp(p);
        break;

    case PktType::UDP:
        if ( p->ptrs.decode_flags & DECODE_FRAG )
            flow_con->process_ip(p);

        if ( p->ptrs.udph )
            flow_con->process_udp(p);
        break;

    case PktType::ICMP:
        if ( p->ptrs.icmph )
            flow_con->process_icmp(p);
        break;

    case PktType::IP:
        if ( p->has_ip() )
            flow_con->process_ip(p);
        break;

    default:
        break;
    }

    MODULE_PROFILE_END(s5PerfStats);
}

#if 0
// FIXIT-L add method to get exp cache?
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

void base_tterm()
{
    delete flow_con;
    flow_con = nullptr;
}

static const InspectApi base_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MOD_NAME,
        MOD_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_STREAM,
    (unsigned)PktType::ANY_IP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // init
    nullptr, // term
    nullptr, // tinit
    base_tterm,
    base_ctor,
    base_dtor,
    nullptr, // ssn
    nullptr  // reset
};

const BaseApi* nin_stream_base = &base_api.base;

