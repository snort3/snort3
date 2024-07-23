//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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
// flow_cache.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/flow_cache.h"

#include <sstream>

#include "control/control.h"
#include "detection/detection_engine.h"
#include "hash/hash_defs.h"
#include "hash/zhash.h"
#include "helpers/flag_context.h"
#include "log/messages.h"
#ifdef REG_TEST
#include "main/analyzer.h"
#endif
#include "main/thread_config.h"
#include "packet_io/active.h"
#include "packet_io/packet_tracer.h"
#include "stream/base/stream_module.h"
#include "stream/tcp/tcp_session.h"
#include "stream/tcp/tcp_trace.h"
#include "time/packet_time.h"
#include "trace/trace_api.h"
#include "utils/stats.h"

#include "flow.h"
#include "flow_key.h"
#include "flow_uni_list.h"
#include "ha.h"
#include "session.h"

using namespace snort;

#define SESSION_CACHE_FLAG_PURGING  0x01

static const unsigned ALLOWED_FLOWS_ONLY = 1;
static const unsigned OFFLOADED_FLOWS_TOO = 2;
static const unsigned ALL_FLOWS = 3;
static const unsigned WDT_MASK = 7; // kick watchdog once for every 8 flows deleted

constexpr uint8_t MAX_PROTOCOLS = (uint8_t)to_utype(PktType::MAX) - 1; //removing PktType::NONE from count
constexpr uint64_t max_skip_protos = (1ULL << MAX_PROTOCOLS) - 1;

uint8_t DumpFlows::dump_code = 0;

#ifndef REG_TEST
DumpFlows::DumpFlows(unsigned count,  ControlConn* conn)
#else
DumpFlows::DumpFlows(unsigned count, ControlConn* conn, int resume)
#endif
    : snort::AnalyzerCommand(conn), dump_count(count)
#ifdef REG_TEST
    , resume(resume)
#endif
{
    next.resize(ThreadConfig::get_instance_max());
    ++dump_code;
}

bool DumpFlows::open_files(const std::string& base_name)
{
    dump_stream.resize(ThreadConfig::get_instance_max());
    for (unsigned i = 0; i < ThreadConfig::get_instance_max(); ++i)
    {
        std::string file_name = base_name + std::to_string(i + 1);
        dump_stream[i].open(file_name, std::fstream::out | std::fstream::trunc);
        if (0 != (dump_stream[i].rdstate() & std::fstream::failbit))
        {
            LogRespond(ctrlcon, "Dump flows failed to open %s\n", file_name.c_str());
            return false;
        }
    }
    return true;
}

void DumpFlows::cidr2mask(const uint32_t cidr, uint32_t* mask) const
{
    size_t i;

    for (i = cidr; i > 0;)
    {
        --i;
        mask[i / 32] |= 0x00000001 << (i % 32);
    }
}

bool DumpFlows::set_ip(std::string filter_ip, snort::SfIp& ip, snort::SfIp& subnet) const
{
    size_t slash_pos = filter_ip.find('/');
    if (slash_pos != std::string::npos)
    {
        std::string ip_part = filter_ip.substr(0, slash_pos);
        std::string subnet_part = filter_ip.substr(slash_pos+1);

        if (ip_part.find(':') != std::string::npos)
        {
            //filter is IPV6
            if (ip.pton(AF_INET6, ip_part.c_str()) != SFIP_SUCCESS)
                return false;

            if (subnet_part.find(':') == std::string::npos)
            {
                //IPV6 cidr
                uint32_t cidr = std::stoi(subnet_part);
                if (cidr > 128)
                    return false;
                uint32_t mask_v6[4]={0};
                cidr2mask(std::stoi(subnet_part), mask_v6);
                if (subnet.set(&mask_v6, AF_INET6) != SFIP_SUCCESS)
                    return false;
            }
            else if (subnet_part.empty() || (subnet.pton(AF_INET6, subnet_part.c_str()) != SFIP_SUCCESS))
                return false;
            return true;
        }
        else if (ip_part.find('.') != std::string::npos)
        {
            //filter is  IPV4
            if (ip.pton(AF_INET, ip_part.c_str()) != SFIP_SUCCESS)
                return false;

            if (subnet_part.find('.') == std::string::npos)
            {
                //IPV4 cidr
                uint32_t cidr = std::stoi(subnet_part);
                if (cidr > 32)
                    return false;
                uint32_t mask_v4[1]={0};
                cidr2mask(std::stoi(subnet_part), mask_v4);
                if (subnet.set(&mask_v4, AF_INET) != SFIP_SUCCESS)
                    return false;
            }
            else if (subnet_part.empty())
                return false;
            else
            {
                //IPV4 netmask
                if (subnet.pton(AF_INET, subnet_part.c_str()) != SFIP_SUCCESS)
                    return false;
            }
            return true;
        }
        return false;
    }
    else
    {
        //No mask
        if (filter_ip.find(':') != std::string::npos)
        {
            return ip.pton(AF_INET6, filter_ip.c_str()) == SFIP_SUCCESS;
        }
        else if (filter_ip.find('.') != std::string::npos)
        {
            return ip.pton(AF_INET, filter_ip.c_str()) == SFIP_SUCCESS;
        }
        else if (filter_ip.empty())
            return true;
    }
    return false;
}

bool DumpFlows::execute(Analyzer&, void**)
{
    if (!flow_con)
        return true;
    unsigned id = get_instance_id();
#ifdef REG_TEST
    if (!next[id] && -1 != resume)
        Analyzer::get_local_analyzer()->resume(resume);
#endif
    bool first = !next[id];
    next[id] = 1;
    return flow_con->dump_flows(dump_stream[id], dump_count, ffc, first, dump_code);
}

//-------------------------------------------------------------------------
// FlowCache stuff
//-------------------------------------------------------------------------

FlowCache::FlowCache(const FlowCacheConfig& cfg) : config(cfg)
{
    hash_table = new ZHash(config.max_flows, sizeof(FlowKey), MAX_PROTOCOLS, false);
    uni_flows = new FlowUniList;
    uni_ip_flows = new FlowUniList;
    flags = 0x0;

    assert(prune_stats.get_total() == 0);
}

FlowCache::~FlowCache()
{
    delete hash_table;
    delete_uni();
}

unsigned FlowCache::get_flows_allocated() const
{
    return hash_table->get_num_nodes();
}

void FlowCache::delete_uni()
{
    delete uni_flows;
    delete uni_ip_flows;

    uni_flows = nullptr;
    uni_ip_flows = nullptr;
}

void FlowCache::push(Flow* flow)
{
    void* key = hash_table->push(flow);
    flow->key = (FlowKey*)key;
}

unsigned FlowCache::get_count()
{
    return hash_table ? hash_table->get_num_nodes() : 0;
}

Flow* FlowCache::find(const FlowKey* key)
{
    Flow* flow = (Flow*)hash_table->get_user_data(key,to_utype(key->pkt_type));
    if ( flow )
    {
        time_t t = packet_time();

        if ( flow->last_data_seen < t )
            flow->last_data_seen = t;
    }

    return flow;
}

// always prepend
void FlowCache::link_uni(Flow* flow)
{
    if ( flow->key->pkt_type == PktType::IP )
    {
        debug_logf(stream_trace, TRACE_FLOW, nullptr,
            "linking unidirectional flow (IP) to list of size: %u\n",
            uni_ip_flows->get_count());
        uni_ip_flows->link_uni(flow);
    }
    else
    {
        debug_logf(stream_trace, TRACE_FLOW, nullptr,
            "linking unidirectional flow (non-IP) to list of size: %u\n",
            uni_flows->get_count());
        uni_flows->link_uni(flow);
    }
}

// but remove from any point
void FlowCache::unlink_uni(Flow* flow)
{
    if ( flow->key->pkt_type == PktType::IP )
    {
        if ( uni_ip_flows->unlink_uni(flow) )
        {
            debug_logf(stream_trace, TRACE_FLOW, nullptr,
                "unlinked unidirectional flow (IP) from list, size: %u\n",
                uni_ip_flows->get_count());
        }
    }
    else
    {
        if ( uni_flows->unlink_uni(flow) )
        {
            debug_logf(stream_trace, TRACE_FLOW, nullptr,
                "unlinked unidirectional flow (non-IP) from list, size: %u\n",
                uni_flows->get_count());
        }
    }
}

Flow* FlowCache::allocate(const FlowKey* key)
{
    // This is called by packet processing and HA consume. This method is only called after a
    // failed attempt to find a flow with this key.
    time_t timestamp = packet_time();
    if ( hash_table->get_num_nodes() >= config.max_flows )
    {
        if ( !prune_idle(timestamp, nullptr) )
        {
            if ( !prune_unis(key->pkt_type) )
                prune_excess(nullptr);
        }
    }

    Flow* flow = new Flow;
    push(flow);

    flow = (Flow*)hash_table->get(key, to_utype(key->pkt_type));
    assert(flow);
    link_uni(flow);
    flow->last_data_seen = timestamp;
    flow->set_idle_timeout(config.proto[to_utype(flow->key->pkt_type)].nominal_timeout);

    return flow;
}

void FlowCache::remove(Flow* flow)
{
    unlink_uni(flow);
    const snort::FlowKey* key = flow->key;
    // Delete before releasing the node, so that the key is valid until the flow is completely freed
    delete flow;
    hash_table->release_node(key, to_utype(key->pkt_type));
}

bool FlowCache::release(Flow* flow, PruneReason reason, bool do_cleanup)
{
    if ( !flow->was_blocked() )
    {
        flow->flush(do_cleanup);
        if ( flow->ssn_state.session_flags & SSNFLAG_KEEP_FLOW )
        {
            flow->ssn_state.session_flags &= ~SSNFLAG_KEEP_FLOW;
            return false;
        }
    }

    flow->reset(do_cleanup);
    prune_stats.update(reason, flow->key->pkt_type);
    remove(flow);
    return true;
}

void FlowCache::retire(Flow* flow)
{
    flow->reset(true);
    prune_stats.update(PruneReason::NONE, flow->key->pkt_type);
    remove(flow);
}

unsigned FlowCache::prune_idle(uint32_t thetime, const Flow* save_me)
{
    ActiveSuspendContext act_susp(Active::ASP_PRUNE);

    unsigned pruned = 0;
    uint64_t skip_protos = 0;

    assert(MAX_PROTOCOLS < 8 * sizeof(skip_protos));

    {
        PacketTracerSuspend pt_susp;
        while ( pruned <= cleanup_flows and 
                skip_protos != max_skip_protos )
        {
            // Round-robin through the proto types
            for( uint8_t proto_idx = 0; proto_idx < MAX_PROTOCOLS; ++proto_idx ) 
            {
                if( pruned > cleanup_flows )
                    break;

                const uint64_t proto_mask = 1ULL << proto_idx;

                if ( skip_protos & proto_mask )
                    continue;

                auto flow = static_cast<Flow*>(hash_table->lru_first(proto_idx));
                if ( !flow )
                {
                    skip_protos |= proto_mask;
                    continue;
                }
                
                if ( flow == save_me // Reached the current flow. This *should* be the newest flow
                    or flow->is_suspended()
                    or flow->last_data_seen + config.pruning_timeout >= thetime )
                {
                    skip_protos |= proto_mask;
                    continue;
                }

                flow->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
                if ( release(flow, PruneReason::IDLE_MAX_FLOWS) )
                    ++pruned;
            }
        }
    }

    if ( PacketTracer::is_active() and pruned )
        PacketTracer::log("Flow: Pruned %u flows\n", pruned);

    return pruned;
}

unsigned FlowCache::prune_unis(PktType pkt_type)
{
    ActiveSuspendContext act_susp(Active::ASP_PRUNE);

    // we may have many or few unis; need to find reasonable ratio
    // FIXIT-M max_uni should be based on typical ratios seen in perfmon
    const unsigned max_uni = (config.max_flows >> 2) + 1;
    unsigned pruned = 0;
    FlowUniList* uni_list;

    {
        PacketTracerSuspend pt_susp;

        if ( pkt_type == PktType::IP )
            uni_list = uni_ip_flows;
        else
            uni_list = uni_flows;

        Flow* flow = uni_list->get_oldest_uni();
        while ( (uni_list->get_count() > max_uni) && flow && (pruned < cleanup_flows) )
        {
            Flow* prune_me = flow;
            flow = uni_list->get_prev(prune_me);

            if ( prune_me->was_blocked() )
                continue;

            if ( release(prune_me, PruneReason::UNI) )
                ++pruned;
        }
    }

    if ( PacketTracer::is_active() and pruned )
        PacketTracer::log("Flow: Pruned %u flows\n", pruned);

    return pruned;
}

unsigned FlowCache::prune_excess(const Flow* save_me)
{
    ActiveSuspendContext act_susp(Active::ASP_PRUNE);

    auto max_cap = config.max_flows - cleanup_flows;
    assert(max_cap > 0);

    unsigned pruned = 0;

    // initially skip offloads but if that doesn't work the hash table is iterated from the
    // beginning again. prune offloads at that point.
    unsigned ignore_offloads = hash_table->get_num_nodes();
    uint64_t skip_protos = 0;

    assert(MAX_PROTOCOLS < 8 * sizeof(skip_protos));


    {
        PacketTracerSuspend pt_susp;
        unsigned blocks = 0;

        while ( true )
        {
            auto num_nodes = hash_table->get_num_nodes();
            if ( num_nodes <= max_cap or num_nodes <= blocks or 
                    ignore_offloads == 0 or skip_protos == max_skip_protos )
                    break;
            
            for( uint8_t proto_idx = 0; proto_idx < MAX_PROTOCOLS; ++proto_idx )  
            {
                num_nodes = hash_table->get_num_nodes();
                if ( num_nodes <= max_cap or num_nodes <= blocks )
                    break;

                const uint64_t proto_mask = 1ULL << proto_idx;

                if ( skip_protos & proto_mask ) 
                    continue;

                auto flow = static_cast<Flow*>(hash_table->lru_first(proto_idx));
                if ( !flow )
                {
                    skip_protos |= proto_mask;
                    continue;
                }

                if ( (save_me and flow == save_me) or flow->was_blocked() or 
                        (flow->is_suspended() and ignore_offloads) )
                {
                    // check for non-null save_me above to silence analyzer
                    // "called C++ object pointer is null" here
                    if ( flow->was_blocked() )
                        ++blocks;
                    // FIXIT-M we should update last_data_seen upon touch to ensure
                    // the hash_table LRU list remains sorted by time
                    hash_table->lru_touch(proto_idx);
                }
                else
                {
                    flow->ssn_state.session_flags |= SSNFLAG_PRUNED;
                    if ( release(flow, PruneReason::EXCESS) )
                        ++pruned;
                }
                if ( ignore_offloads > 0 )
                    --ignore_offloads;
            }
        }

        if ( !pruned and hash_table->get_num_nodes() > max_cap )
        {
            pruned += prune_multiple(PruneReason::EXCESS, true);
        }
    }

    if ( PacketTracer::is_active() and pruned )
        PacketTracer::log("Flow: Pruned %u flows\n", pruned);

    return pruned;
}

bool FlowCache::prune_one(PruneReason reason, bool do_cleanup, uint8_t type)
{
    // so we don't prune the current flow (assume current == MRU)
    if ( hash_table->get_num_nodes() <= 1 )
        return false;

    // ZHash returns in LRU order, which is updated per packet via find --> move_to_front call
    auto flow = static_cast<Flow*>(hash_table->lru_first(type));
    if( !flow )
        return false;

    flow->ssn_state.session_flags |= SSNFLAG_PRUNED;
    release(flow, reason, do_cleanup);

    return true;
}

unsigned FlowCache::prune_multiple(PruneReason reason, bool do_cleanup)
{
    unsigned pruned = 0;
    // so we don't prune the current flow (assume current == MRU)
    if ( hash_table->get_num_nodes() <= 1 )
        return 0;
    
    uint8_t proto = 0;
    uint64_t skip_protos = 0;

    assert(MAX_PROTOCOLS < 8 * sizeof(skip_protos));

    
    while ( pruned < config.prune_flows )
    {
        const uint64_t proto_mask = 1ULL << proto;
        if ( (skip_protos & proto_mask) or !prune_one(reason, do_cleanup, proto) )
        {

            skip_protos |= proto_mask;
            if ( skip_protos == max_skip_protos )
                break;
        }
        else
            pruned++;
       
        if ( ++proto >= MAX_PROTOCOLS )
            proto = 0;
    }

    if ( PacketTracer::is_active() and pruned )
        PacketTracer::log("Flow: Pruned memcap %u flows\n", pruned);

    return pruned;
}

unsigned FlowCache::timeout(unsigned num_flows, time_t thetime)
{
    ActiveSuspendContext act_susp(Active::ASP_TIMEOUT);

    unsigned retired = 0;
    uint64_t skip_protos = 0;

    assert(MAX_PROTOCOLS < 8 * sizeof(skip_protos));

    {
        PacketTracerSuspend pt_susp;

        while ( retired < num_flows and skip_protos != max_skip_protos )
        {
            for( uint8_t proto_idx = 0; proto_idx < MAX_PROTOCOLS; ++proto_idx ) 
            {
                if( retired >= num_flows )
                    break;
                
                const uint64_t proto_mask = 1ULL << proto_idx;

                if ( skip_protos & proto_mask ) 
                    continue;

                auto flow = static_cast<Flow*>(hash_table->lru_current(proto_idx));
                if ( !flow )
                    flow = static_cast<Flow*>(hash_table->lru_first(proto_idx));
                if ( !flow )
                {
                    skip_protos |= proto_mask;
                    continue;
                }

                if ( flow->is_hard_expiration() )
                {
                    if ( flow->expire_time > static_cast<uint64_t>(thetime) )
                    {
                        skip_protos |= proto_mask;
                        continue;
                    }
                }
                else if ( flow->last_data_seen + flow->idle_timeout > thetime )
                {
                    skip_protos |= proto_mask;
                    continue;
                }

                if ( HighAvailabilityManager::in_standby(flow) or flow->is_suspended() )
                    continue;

                flow->ssn_state.session_flags |= SSNFLAG_TIMEDOUT;
                if ( release(flow, PruneReason::IDLE_PROTOCOL_TIMEOUT) )
                    ++retired;
            }
        }
    }

    if ( PacketTracer::is_active() and retired )
        PacketTracer::log("Flow: Timed out %u flows\n", retired);

    return retired;
}

unsigned FlowCache::delete_active_flows(unsigned mode, unsigned num_to_delete, unsigned &deleted)
{
    uint64_t skip_protos = 0;
    uint64_t undeletable = 0;

    assert(MAX_PROTOCOLS < 8 * sizeof(skip_protos));


    while ( num_to_delete and skip_protos != max_skip_protos and
            undeletable < hash_table->get_num_nodes() )
    {
        for( uint8_t proto_idx = 0; proto_idx < MAX_PROTOCOLS; ++proto_idx ) 
        {
            if( num_to_delete == 0)
                break;
            
            const uint64_t proto_mask = 1ULL << proto_idx;

            if ( skip_protos & proto_mask )
                continue;
            
            auto flow = static_cast<Flow*>(hash_table->lru_first(proto_idx));
            if ( !flow )
            {
                skip_protos |= proto_mask;
                continue;
            }

            if ( (mode == ALLOWED_FLOWS_ONLY and (flow->was_blocked() or flow->is_suspended()))
                or (mode == OFFLOADED_FLOWS_TOO and flow->was_blocked()) )
            {
                undeletable++;
                hash_table->lru_touch(proto_idx);
                continue;
            }

            if ( (deleted & WDT_MASK) == 0 )
                ThreadConfig::preemptive_kick();

            unlink_uni(flow);

            if ( flow->was_blocked() )
                delete_stats.update(FlowDeleteState::BLOCKED);
            else if ( flow->is_suspended() )
                delete_stats.update(FlowDeleteState::OFFLOADED);
            else
                delete_stats.update(FlowDeleteState::ALLOWED);

            flow->reset(true);
            // Delete before removing the node, so that the key is valid until the flow is completely freed
            delete flow;
            // The flow should not be removed from the hash before reset
            hash_table->remove(proto_idx);
            ++deleted;
            --num_to_delete;
        }
    }
    return num_to_delete;
}

unsigned FlowCache::delete_flows(unsigned num_to_delete)
{
    ActiveSuspendContext act_susp(Active::ASP_RELOAD);

    unsigned deleted = 0;

    {
        PacketTracerSuspend pt_susp;

        for ( unsigned mode = ALLOWED_FLOWS_ONLY; num_to_delete && mode <= ALL_FLOWS; ++mode )
            num_to_delete = delete_active_flows(mode, num_to_delete, deleted);
    }

    if ( PacketTracer::is_active() and deleted )
        PacketTracer::log("Flow: Deleted %u flows\n", deleted);

    return deleted;
}

// Remove all flows from the hash table.
unsigned FlowCache::purge()
{
    ActiveSuspendContext act_susp(Active::ASP_EXIT);
    FlagContext<decltype(flags)>(flags, SESSION_CACHE_FLAG_PURGING);

    unsigned retired = 0;

    for( uint8_t proto_idx = 0; proto_idx < MAX_PROTOCOLS; ++proto_idx ) 
    {
        while ( auto flow = static_cast<Flow*>(hash_table->lru_first(proto_idx)) )
        {
            retire(flow);
            ++retired;
        }
    }
    // Remove these here so alloc/dealloc counts are right when Memory::get_pegs is called
    delete_uni();
    return retired;
}

std::string FlowCache::timeout_to_str(time_t t)
{
    std::stringstream out;
    time_t hours = t / (60 * 60);
    if (hours)
    {
        out << hours << "h";
        t -= hours * (60 * 60);
    }
    time_t minutes = t / 60;
    if (minutes || hours)
    {
        out << minutes << "m";
        t -= minutes * 60;
    }
    if (t || !hours)
        out << t << "s";
    return out.str();
}


bool FlowCache::is_ip_match(const SfIp& flow_sfip, const SfIp& filter_sfip, const SfIp& filter_subnet_sfip) const
{
    //if address is empty
    if (!filter_sfip.is_set())
        return true;

    //if no subnet mask
    if (!filter_subnet_sfip.is_set())
    {
        return filter_sfip.fast_equals_raw(flow_sfip);
    }
    else
    {
        if (filter_sfip.get_family() != flow_sfip.get_family())
            return false;
        const uint64_t* filter_ptr = filter_sfip.get_ip64_ptr();
        const uint64_t* flow_ptr = flow_sfip.get_ip64_ptr();
        const uint64_t* subnet_sfip = filter_subnet_sfip.get_ip64_ptr();
        return (filter_ptr[0] & subnet_sfip[0]) == (flow_ptr[0] & subnet_sfip[0]) && (filter_ptr[1] & subnet_sfip[1]) == (flow_ptr[1] & subnet_sfip[1]);
    }
}

bool FlowCache::filter_flows(const Flow& flow, const FilterFlowCriteria& ffc) const
{
    const SfIp& flow_srcip = flow.flags.client_initiated ? flow.client_ip : flow.server_ip;
    const SfIp& flow_dstip = flow.flags.client_initiated ? flow.server_ip : flow.client_ip;

    return ((ffc.pkt_type == PktType::NONE || flow.pkt_type == ffc.pkt_type)
            && is_ip_match(flow_srcip, ffc.source_sfip, ffc.source_subnet_sfip)
            && is_ip_match(flow_dstip, ffc.destination_sfip, ffc.destination_subnet_sfip)
            && (!ffc.source_port || ffc.source_port == (flow.flags.key_is_reversed ? flow.key->port_h : flow.key->port_l))
            && (!ffc.destination_port || ffc.destination_port == (flow.flags.key_is_reversed ? flow.key->port_l : flow.key->port_h)));

}

void FlowCache::output_flow(std::fstream& stream, const Flow& flow, const struct timeval& now) const
{
    char src_ip[INET6_ADDRSTRLEN];
    src_ip[0] = 0;
    char dst_ip[INET6_ADDRSTRLEN];
    dst_ip[0] = 0;
    uint16_t src_port;
    uint16_t dst_port;
    if (flow.flags.key_is_reversed)
    {
        SfIp ip;
        ip.set(flow.key->ip_h);
        ip.ntop(src_ip, sizeof(src_ip));
        ip.set(flow.key->ip_l);
        ip.ntop(dst_ip, sizeof(dst_ip));
        src_port = flow.key->port_h;
        dst_port = flow.key->port_l;
    }
    else
    {
        SfIp ip;
        ip.set(flow.key->ip_l);
        ip.ntop(src_ip, sizeof(src_ip));
        ip.set(flow.key->ip_h);
        ip.ntop(dst_ip, sizeof(dst_ip));
        src_port = flow.key->port_l;
        dst_port = flow.key->port_h;
    }
    std::stringstream out;
    std::stringstream proto;
    switch ( flow.pkt_type )
    {
        case PktType::IP:
            out << "IP " << flow.key->addressSpaceId << ": " << src_ip << " " << dst_ip;
            break;

        case PktType::ICMP:
            out << "ICMP " << flow.key->addressSpaceId << ": " << src_ip << " type " << src_port << " "
                << dst_ip;
            break;

        case PktType::TCP:
            out << "TCP " << flow.key->addressSpaceId << ": " << src_ip << "/" << src_port << " "
                << dst_ip << "/" << dst_port;
            if (flow.session)
            {
                TcpSession* tcp_session = static_cast<TcpSession*>(flow.session);
                proto << " state client " << stream_tcp_state_to_str(tcp_session->client)
                    << " server " << stream_tcp_state_to_str(tcp_session->server);
            }
            break;

        case PktType::UDP:
            out << "UDP " << flow.key->addressSpaceId << ": "<< src_ip << "/" << src_port << " "
                << dst_ip << "/" << dst_port;
            break;

        default:
            assert(false);
    }
    out << " pkts/bytes client " << flow.flowstats.client_pkts << "/" << flow.flowstats.client_bytes
        << " server " << flow.flowstats.server_pkts << "/" << flow.flowstats.server_bytes
        << " idle " << (now.tv_sec - flow.last_data_seen) << "s, uptime "
        << (now.tv_sec - flow.flowstats.start_time.tv_sec) << "s, timeout ";
    std::string t = flow.is_hard_expiration() ?
        timeout_to_str(flow.expire_time - now.tv_sec) :
        timeout_to_str((flow.last_data_seen + config.proto[to_utype(flow.key->pkt_type)].nominal_timeout) - now.tv_sec);
    out << t;
    stream << out.str() << proto.str() << std::endl;
}

bool FlowCache::dump_flows(std::fstream& stream, unsigned count, const FilterFlowCriteria& ffc, bool first, uint8_t code) const
{
    struct timeval now;
    packet_gettimeofday(&now);
    unsigned i;

    for(uint8_t proto_id = to_utype(PktType::NONE)+1; proto_id <= to_utype(PktType::ICMP); proto_id++)
    {
        if (first)
        {
            Flow* walk_flow = static_cast<Flow*>(hash_table->get_walk_user_data(proto_id));
            if (!walk_flow)
            {
                //Return only if all the protocol caches are processed.
                if (proto_id < to_utype(PktType::ICMP))
                    continue;

                return true;
            }
            walk_flow->dump_code = code;
            bool matched_filter = filter_flows(*walk_flow, ffc);
            if (matched_filter)
                output_flow(stream, *walk_flow, now);
            i = 1;

        }
        else
            i = 0;
        while (i < count)
        {
            Flow* walk_flow = static_cast<Flow*>(hash_table->get_next_walk_user_data(proto_id));

            if (!walk_flow )
            {
                //Return only if all the protocol caches are processed.
                if (proto_id < to_utype(PktType::ICMP))
                    break;
                return true;
            }
            if (walk_flow->dump_code != code)
            {
                walk_flow->dump_code = code;
                bool matched_filter = filter_flows(*walk_flow, ffc);
                if (matched_filter)
                    output_flow(stream, *walk_flow, now);
                ++i;
            }
#ifdef REG_TEST
            else
                LogMessage("dump_flows skipping already dumped flow\n");
#endif
        }
    }
    return false;
}

size_t FlowCache::uni_flows_size() const
{
    return uni_flows ? uni_flows->get_count() : 0;
}

size_t FlowCache::uni_ip_flows_size() const
{
    return uni_ip_flows ? uni_ip_flows->get_count() : 0;
}

size_t FlowCache::flows_size() const
{
    return hash_table->get_num_nodes();
}
