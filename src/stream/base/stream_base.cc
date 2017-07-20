//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/flow_control.h"
#include "flow/prune_stats.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"
#include "stream/flush_bucket.h"

#include "stream_ha.h"
#include "stream_module.h"

//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------

THREAD_LOCAL ProfileStats s5PerfStats;
THREAD_LOCAL FlowControl* flow_con = nullptr;

static BaseStats g_stats;
THREAD_LOCAL BaseStats stream_base_stats;

#define PROTO_PEGS(proto_str) \
    { proto_str "_flows", "total " proto_str " sessions" }, \
    { proto_str "_total_prunes", "total " proto_str " sessions pruned" }, \
    { proto_str "_idle_prunes", proto_str " sessions pruned due to timeout" }, \
    { proto_str "_excess_prunes", proto_str " sessions pruned due to excess" }, \
    { proto_str "_uni_prunes", proto_str " uni sessions pruned" }, \
    { proto_str "_preemptive_prunes", proto_str " sessions pruned during preemptive pruning" }, \
    { proto_str "_memcap_prunes", proto_str " sessions pruned due to memcap" }, \
    { proto_str "_ha_prunes", proto_str " sessions pruned by high availability sync" }

#define SET_PROTO_COUNTS(proto, pkttype) \
    stream_base_stats.proto ## _flows = flow_con->get_flows(PktType::pkttype); \
    stream_base_stats.proto ## _total_prunes = flow_con->get_total_prunes(PktType::pkttype), \
    stream_base_stats.proto ## _timeout_prunes = \
        flow_con->get_prunes(PktType::pkttype, PruneReason::IDLE), \
    stream_base_stats.proto ## _excess_prunes = \
        flow_con->get_prunes(PktType::pkttype, PruneReason::EXCESS), \
    stream_base_stats.proto ## _uni_prunes = \
        flow_con->get_prunes(PktType::pkttype, PruneReason::UNI), \
    stream_base_stats.proto ## _preemptive_prunes = \
        flow_con->get_prunes(PktType::pkttype, PruneReason::PREEMPTIVE), \
    stream_base_stats.proto ## _memcap_prunes = \
        flow_con->get_prunes(PktType::pkttype, PruneReason::MEMCAP), \
    stream_base_stats.proto ## _ha_prunes = \
        flow_con->get_prunes(PktType::pkttype, PruneReason::HA)

// FIXIT-L dependency on stats define in another file
const PegInfo base_pegs[] =
{
    PROTO_PEGS("ip"),
    PROTO_PEGS("icmp"),
    PROTO_PEGS("tcp"),
    PROTO_PEGS("udp"),
    PROTO_PEGS("user"),
    PROTO_PEGS("file"),
    { nullptr, nullptr }
};

// FIXIT-L dependency on stats define in another file
void base_sum()
{
    if ( !flow_con )
        return;

    SET_PROTO_COUNTS(ip, IP);
    SET_PROTO_COUNTS(icmp, ICMP);
    SET_PROTO_COUNTS(tcp, TCP);
    SET_PROTO_COUNTS(udp, UDP);
    SET_PROTO_COUNTS(user, PDU);
    SET_PROTO_COUNTS(file, FILE);

    sum_stats((PegCount*)&g_stats, (PegCount*)&stream_base_stats,
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

    memset(&stream_base_stats, 0, sizeof(stream_base_stats));
}

//-------------------------------------------------------------------------
// runtime support
//-------------------------------------------------------------------------

static inline bool is_eligible(Packet* p)
{
    // FIXIT-M extra check?  bad checksums should be removed in detect.c snort_inspect()
    if ( p->ptrs.decode_flags & DECODE_ERR_CKSUM_IP )
        return false;

    if ( p->packet_flags & PKT_REBUILT_STREAM )
        return false;

    if ( !p->ptrs.ip_api.is_valid() )
        return false;

    return true;
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
    StreamModuleConfig config;
};

StreamBase::StreamBase(const StreamModuleConfig* c)
{ config = *c; }

void StreamBase::tinit()
{
    assert(!flow_con);
    flow_con = new FlowControl;
    InspectSsnFunc f;

    StreamHAManager::tinit();

    if ( config.ip_cfg.max_sessions )
    {
        if ( (f = InspectorManager::get_session((uint16_t)PktType::IP)) )
            flow_con->init_ip(config.ip_cfg, f);
    }
    if ( config.icmp_cfg.max_sessions )
    {
        if ( (f = InspectorManager::get_session((uint16_t)PktType::ICMP)) )
            flow_con->init_icmp(config.icmp_cfg, f);
    }
    if ( config.tcp_cfg.max_sessions )
    {
        if ( (f = InspectorManager::get_session((uint16_t)PktType::TCP)) )
            flow_con->init_tcp(config.tcp_cfg, f);
    }
    if ( config.udp_cfg.max_sessions )
    {
        if ( (f = InspectorManager::get_session((uint16_t)PktType::UDP)) )
            flow_con->init_udp(config.udp_cfg, f);
    }
    if ( config.user_cfg.max_sessions )
    {
        if ( (f = InspectorManager::get_session((uint16_t)PktType::PDU)) )
            flow_con->init_user(config.user_cfg, f);
    }
    if ( config.file_cfg.max_sessions )
    {
        if ( (f = InspectorManager::get_session((uint16_t)PktType::FILE)) )
            flow_con->init_file(config.file_cfg, f);
    }
    uint32_t max = config.tcp_cfg.max_sessions + config.udp_cfg.max_sessions
        + config.user_cfg.max_sessions;

    if ( max > 0 )
        flow_con->init_exp(max);

    FlushBucket::set(config.footprint);
}

void StreamBase::tterm()
{
    StreamHAManager::tterm();
    FlushBucket::clear();
}

void StreamBase::show(SnortConfig*)
{
    // FIXIT-L SSN print
    //StreamPrintGlobalConfig(&config);
}

void StreamBase::eval(Packet* p)
{
    Profile profile(s5PerfStats);

    if ( !is_eligible(p) )
        return;

    switch ( p->type() )
    {
    case PktType::IP:
        if ( p->has_ip() and
            ((p->ptrs.decode_flags & DECODE_FRAG) or !config.ip_frags_only) )
            flow_con->process_ip(p);
        break;

    case PktType::ICMP:
        if ( p->ptrs.icmph )
            flow_con->process_icmp(p);
        break;

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

    case PktType::PDU:
        flow_con->process_user(p);
        break;

    case PktType::FILE:
        flow_con->process_file(p);
        break;

    default:
        break;
    }
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

static void base_tterm()
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
    (unsigned)PktType::ANY_SSN,
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

