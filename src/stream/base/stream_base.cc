//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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

#include <functional>
#include <mutex>

#include "detection/ips_context.h"
#include "flow/expect_cache.h"
#include "flow/flow_control.h"
#include "flow/prune_stats.h"
#include "framework/data_bus.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "main/snort_types.h"
#include "managers/inspector_manager.h"
#include "profiler/profiler_defs.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"
#include "pub_sub/stream_event_ids.h"
#include "stream/flush_bucket.h"
#include "stream/stream.h"
#include "stream/tcp/tcp_stream_tracker.h"

#include "stream_ha.h"
#include "stream_module.h"

using namespace snort;

//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------

THREAD_LOCAL ProfileStats s5PerfStats;
THREAD_LOCAL FlowControl* flow_con = nullptr;

std::vector<FlowControl *> crash_dump_flow_control;
static std::mutex crash_dump_flow_control_mutex;

THREAD_LOCAL BaseStats stream_base_stats;


// FIXIT-L dependency on stats define in another file
const PegInfo base_pegs[] =
{
    { CountType::SUM, "flows", "total sessions" },
    { CountType::SUM, "total_prunes", "total sessions pruned" },
	{ CountType::SUM, "idle_prunes_max_flows", " sessions pruned due to pruning timeout since max flows is reached" },
	{ CountType::SUM, "idle_prunes_proto_timeout", " sessions pruned due to protocol timeout" },
    { CountType::SUM, "excess_prunes", "sessions pruned due to excess" },
    { CountType::SUM, "uni_prunes", "uni sessions pruned" },
    { CountType::SUM, "memcap_prunes", "sessions pruned due to memcap" },
    { CountType::SUM, "ha_prunes", "sessions pruned by high availability sync" },
    { CountType::SUM, "stale_prunes", "sessions pruned due to stale connection" },
    { CountType::SUM, "expected_flows", "total expected flows created within snort" },
    { CountType::SUM, "expected_realized", "number of expected flows realized" },
    { CountType::SUM, "expected_pruned", "number of expected flows pruned" },
    { CountType::SUM, "expected_overflows", "number of expected cache overflows" },
    { CountType::SUM, "reload_tuning_idle", "number of times stream resource tuner called while idle" },
    { CountType::SUM, "reload_tuning_packets", "number of times stream resource tuner called while processing packets" },
    { CountType::SUM, "reload_total_adds", "number of flows added by config reloads" },
    { CountType::SUM, "reload_total_deletes", "number of flows deleted by config reloads" },
    { CountType::SUM, "reload_freelist_deletes", "number of flows deleted from the free list by config reloads" },
    { CountType::SUM, "reload_allowed_deletes", "number of allowed flows deleted by config reloads" },
    { CountType::SUM, "reload_blocked_deletes", "number of blocked flows deleted by config reloads" },
    { CountType::SUM, "reload_offloaded_deletes", "number of offloaded flows deleted by config reloads" },
    { CountType::SUM, "ip_timeout_prunes", "number of IP flows pruned due to timeout" },
    { CountType::SUM, "tcp_timeout_prunes", "number of TCP flows pruned due to timeout" },
    { CountType::SUM, "udp_timeout_prunes", "number of UDP flows pruned due to timeout" },
    { CountType::SUM, "icmp_timeout_prunes", "number of ICMP flows pruned due to timeout" },
    { CountType::SUM, "user_timeout_prunes", "number of USER flows pruned due to timeout" },
    { CountType::SUM, "file_timeout_prunes", "number of FILE flows pruned due to timeout" },
    { CountType::SUM, "pdu_timeout_prunes", "number of PDU flows pruned due to timeout" },
    { CountType::SUM, "ip_memcap_prunes", "number of IP flows pruned due to memcap" },
    { CountType::SUM, "tcp_memcap_prunes", "number of TCP flows pruned due to memcap" },
    { CountType::SUM, "udp_memcap_prunes", "number of UDP flows pruned due to memcap" },
    { CountType::SUM, "icmp_memcap_prunes", "number of ICMP flows pruned due to memcap" },
    { CountType::SUM, "user_memcap_prunes", "number of USER flows pruned due to memcap" },
    { CountType::SUM, "file_memcap_prunes", "number of FILE flows pruned due to memcap" },
    { CountType::SUM, "pdu_memcap_prunes", "number of PDU flows pruned due to memcap" },
    { CountType::SUM, "allowlist_memcap_prunes", "number of allowlist flows pruned due to memcap" },
    { CountType::SUM, "excess_to_allowlist", "number of flows moved to the allowlist due to excess" },

    // Keep the NOW stats at the bottom as it requires special sum_stats logic
    { CountType::NOW, "allowlist_flows", "number of flows moved to the allowlist" },
    { CountType::NOW, "current_flows", "current number of flows in cache" },
    { CountType::NOW, "uni_flows", "number of uni flows in cache" },
    { CountType::NOW, "uni_ip_flows", "number of uni ip flows in cache" },
    { CountType::END, nullptr, nullptr }
};

#define NOW_PEGS_NUM 4

// FIXIT-L dependency on stats define in another file
void base_prep()
{
    if ( !flow_con )
        return;

    stream_base_stats.flows = flow_con->get_flows();
    stream_base_stats.prunes = flow_con->get_total_prunes();
    stream_base_stats.max_flow_prunes = flow_con->get_prunes(PruneReason::IDLE_MAX_FLOWS);
    stream_base_stats.protocol_timeout_prunes = flow_con->get_prunes(PruneReason::IDLE_PROTOCOL_TIMEOUT);
    stream_base_stats.excess_prunes = flow_con->get_prunes(PruneReason::EXCESS);
    stream_base_stats.uni_prunes = flow_con->get_prunes(PruneReason::UNI);
    stream_base_stats.memcap_prunes = flow_con->get_prunes(PruneReason::MEMCAP);
    stream_base_stats.ha_prunes = flow_con->get_prunes(PruneReason::HA);
    stream_base_stats.stale_prunes = flow_con->get_prunes(PruneReason::STALE);
    stream_base_stats.reload_freelist_flow_deletes = flow_con->get_deletes(FlowDeleteState::FREELIST);
    stream_base_stats.reload_allowed_flow_deletes = flow_con->get_deletes(FlowDeleteState::ALLOWED);
    stream_base_stats.reload_offloaded_flow_deletes= flow_con->get_deletes(FlowDeleteState::OFFLOADED);
    stream_base_stats.reload_blocked_flow_deletes= flow_con->get_deletes(FlowDeleteState::BLOCKED);
    stream_base_stats.ip_timeout_prunes = flow_con->get_proto_prune_count(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::IP);
    stream_base_stats.tcp_timeout_prunes = flow_con->get_proto_prune_count(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::TCP);
    stream_base_stats.udp_timeout_prunes = flow_con->get_proto_prune_count(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::UDP);
    stream_base_stats.icmp_timeout_prunes = flow_con->get_proto_prune_count(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::ICMP);
    stream_base_stats.user_timeout_prunes = flow_con->get_proto_prune_count(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::USER);
    stream_base_stats.file_timeout_prunes = flow_con->get_proto_prune_count(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::FILE);
    stream_base_stats.pdu_timeout_prunes = flow_con->get_proto_prune_count(PruneReason::IDLE_PROTOCOL_TIMEOUT, PktType::PDU);
    stream_base_stats.ip_memcap_prunes = flow_con->get_proto_prune_count(PruneReason::MEMCAP, PktType::IP);
    stream_base_stats.tcp_memcap_prunes = flow_con->get_proto_prune_count(PruneReason::MEMCAP, PktType::TCP);
    stream_base_stats.udp_memcap_prunes = flow_con->get_proto_prune_count(PruneReason::MEMCAP, PktType::UDP);
    stream_base_stats.icmp_memcap_prunes = flow_con->get_proto_prune_count(PruneReason::MEMCAP, PktType::ICMP);
    stream_base_stats.user_memcap_prunes = flow_con->get_proto_prune_count(PruneReason::MEMCAP, PktType::USER);
    stream_base_stats.file_memcap_prunes = flow_con->get_proto_prune_count(PruneReason::MEMCAP, PktType::FILE);
    stream_base_stats.pdu_memcap_prunes = flow_con->get_proto_prune_count(PruneReason::MEMCAP, PktType::PDU);
    stream_base_stats.allowlist_memcap_prunes = flow_con->get_proto_prune_count(PruneReason::MEMCAP, static_cast<PktType>(allowlist_lru_index));
    stream_base_stats.excess_to_allowlist = flow_con->get_excess_to_allowlist_count();

    stream_base_stats.allowlist_flows = flow_con->get_allowlist_flow_count();
    stream_base_stats.current_flows = flow_con->get_num_flows();
    stream_base_stats.uni_flows = flow_con->get_uni_flows();
    stream_base_stats.uni_ip_flows = flow_con->get_uni_ip_flows();

    ExpectCache* exp_cache = flow_con->get_exp_cache();

    if ( exp_cache )
    {
        stream_base_stats.expected_flows = exp_cache->get_expects();
        stream_base_stats.expected_realized = exp_cache->get_realized();
        stream_base_stats.expected_pruned = exp_cache->get_prunes();
        stream_base_stats.expected_overflows = exp_cache->get_overflows();
    }
}

void base_reset()
{
    memset(&stream_base_stats, 0, sizeof(stream_base_stats));

    if ( flow_con )
    {
        flow_con->clear_counts();
        ExpectCache* exp_cache = flow_con->get_exp_cache();
        if ( exp_cache )
            exp_cache->reset_stats();
    }
}

//-------------------------------------------------------------------------
// runtime support
//-------------------------------------------------------------------------

static inline bool is_eligible(Packet* p)
{
#ifdef NDEBUG
    UNUSED(p);
#endif
    assert(!(p->ptrs.decode_flags & DECODE_ERR_CKSUM_IP));
    assert(!(p->packet_flags & PKT_REBUILT_STREAM));
    assert(p->ptrs.ip_api.is_valid());

    return true;
}


//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

class StreamBase : public Inspector
{
public:
    StreamBase(const StreamModuleConfig*);
    bool configure(SnortConfig*) override;
    void show(const SnortConfig*) const override;

    void tear_down(SnortConfig*) override;

    void tinit() override;
    void tterm() override;

    void eval(Packet*) override;

public:
    StreamModuleConfig config;
};

StreamBase::StreamBase(const StreamModuleConfig* c) : config(*c)
{ }

bool StreamBase::configure(SnortConfig*)
{
    Stream::set_pub_id();
    return true;
}

void StreamBase::tear_down(SnortConfig* sc)
{ sc->register_reload_handler(new StreamUnloadReloadResourceManager); }

void StreamBase::tinit()
{
    assert(!flow_con && config.flow_cache_cfg.max_flows);

    // this is temp added to suppress the compiler error only
    flow_con = new FlowControl(config.flow_cache_cfg);

    std::unique_lock<std::mutex> flow_control_lock(crash_dump_flow_control_mutex);
    crash_dump_flow_control.push_back(flow_con);
    flow_control_lock.unlock();

    InspectSsnFunc f;

    StreamHAManager::tinit();

    if ( (f = InspectorManager::get_session(PROTO_BIT__IP)) )
        flow_con->init_proto(PktType::IP, f);

    if ( (f = InspectorManager::get_session(PROTO_BIT__ICMP)) )
        flow_con->init_proto(PktType::ICMP, f);

    if ( (f = InspectorManager::get_session(PROTO_BIT__TCP)) )
        flow_con->init_proto(PktType::TCP, f);

    if ( (f = InspectorManager::get_session(PROTO_BIT__UDP)) )
        flow_con->init_proto(PktType::UDP, f);

    if ( (f = InspectorManager::get_session(PROTO_BIT__USER)) )
        flow_con->init_proto(PktType::USER, f);

    if ( (f = InspectorManager::get_session(PROTO_BIT__FILE)) )
        flow_con->init_proto(PktType::FILE, f);

    if ( config.flow_cache_cfg.max_flows > 0 )
        flow_con->init_exp(config.flow_cache_cfg.max_flows);

    TcpStreamTracker::set_held_packet_timeout(config.held_packet_timeout);

#ifdef REG_TEST
    FlushBucket::set(config.footprint);
#else
    FlushBucket::set();
#endif
}

void StreamBase::tterm()
{
    StreamHAManager::tterm();
    FlushBucket::clear();
    base_prep();
    delete flow_con;
    flow_con = nullptr;
}

void StreamBase::show(const SnortConfig* sc) const
{
    if ( sc )
        ConfigLogger::log_flag("ip_frags_only", sc->ip_frags_only());
    config.show();
}

void StreamBase::eval(Packet* p)
{
    Profile profile(s5PerfStats);

    if ( !is_eligible(p) )
        return;

    switch ( p->type() )
    {
    case PktType::NONE:
        break;

    case PktType::IP:
        if ( p->has_ip() and ((p->ptrs.decode_flags & DECODE_FRAG) or
            !p->context->conf->ip_frags_only()) )
        {
            bool new_flow = false;
            flow_con->process(PktType::IP, p, &new_flow);
            if ( new_flow )
                DataBus::publish(Stream::get_pub_id(), StreamEventIds::IP_NEW_FLOW, p);
        }
        break;

    case PktType::TCP:
        if ( p->ptrs.tcph )
            flow_con->process(PktType::TCP, p);
        break;

    case PktType::UDP:
        if ( p->ptrs.decode_flags & DECODE_FRAG )
            flow_con->process(PktType::IP, p);

        if ( p->ptrs.udph )
        {
            bool new_flow = false;
            flow_con->process(PktType::UDP, p, &new_flow);
            if ( new_flow )
                DataBus::publish(Stream::get_pub_id(), StreamEventIds::UDP_NEW_FLOW, p);
        }
        break;

    case PktType::ICMP:
        if ( p->ptrs.icmph )
        {
            bool new_flow = false;
            if ( !flow_con->process(PktType::ICMP, p, &new_flow) )
                flow_con->process(PktType::IP, p, &new_flow);
            if ( new_flow )
                DataBus::publish(Stream::get_pub_id(), StreamEventIds::ICMP_NEW_FLOW, p);
        }
        break;

    case PktType::USER:
        flow_con->process(PktType::USER, p);
        break;

    case PktType::FILE:
        flow_con->process(PktType::FILE, p);
        break;

    default:
        break;
    }
}

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

static void base_tinit()
{
    TcpStreamTracker::thread_init();
}

static void base_tterm()
{
    StreamHAManager::tterm();
    FlushBucket::clear();
    TcpStreamTracker::thread_term();
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
    PROTO_BIT__ANY_SSN,
    nullptr, // buffers
    nullptr, // service
    nullptr, // init
    nullptr, // term
    base_tinit,
    base_tterm,
    base_ctor,
    base_dtor,
    nullptr, // ssn
    nullptr  // reset
};

const BaseApi* nin_stream_base = &base_api.base;
