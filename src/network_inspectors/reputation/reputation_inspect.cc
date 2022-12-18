//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

// reputation_inspect.cc author Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "reputation_inspect.h"

#include "detection/detect.h"
#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "log/messages.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "managers/inspector_manager.h"
#include "network_inspectors/packet_tracer/packet_tracer.h"
#include "packet_io/active.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "pub_sub/auxiliary_ip_event.h"
#include "pub_sub/reputation_events.h"
#include "utils/util.h"

#include "reputation_parse.h"

using namespace snort;

THREAD_LOCAL ProfileStats reputation_perf_stats;
THREAD_LOCAL ReputationStats reputationstats;

static unsigned pub_id = 0;

const PegInfo reputation_peg_names[] =
{
{ CountType::SUM, "packets", "total packets processed" },
{ CountType::SUM, "blocked", "number of packets blocked" },
{ CountType::SUM, "trusted", "number of packets trusted" },
{ CountType::SUM, "monitored", "number of packets monitored" },
{ CountType::SUM, "memory_allocated", "total memory allocated" },
{ CountType::SUM, "aux_ip_blocked", "number of auxiliary ip packets blocked" },
{ CountType::SUM, "aux_ip_trusted", "number of auxiliary ip packets trusted" },
{ CountType::SUM, "aux_ip_monitored", "number of auxiliary ip packets monitored" },
{ CountType::END, nullptr, nullptr }
};

#define MANIFEST_FILENAME "interface.info"

static inline IPrepInfo* reputation_lookup(const ReputationConfig& config,
    ReputationData& data, const SfIp* ip)
{
    if (!config.scanlocal)
    {
        if (ip->is_private() )
            return nullptr;
    }

    return (IPrepInfo*)sfrt_flat_dir8x_lookup(ip, data.ip_list);
}

static inline IPdecision get_reputation(const ReputationConfig& config, ReputationData& data,
    IPrepInfo* rep_info, uint32_t& listid, uint32_t ingress_intf, uint32_t egress_intf)
{
    IPdecision decision = DECISION_NULL;

    /*Walk through the IPrepInfo lists*/
    uint8_t* base = (uint8_t*)data.ip_list;
    ListFiles& list_info = data.list_files;

    while (rep_info)
    {
        int i;
        for (i = 0; i < NUM_INDEX_PER_ENTRY; i++)
        {
            uint8_t list_index = rep_info->list_indexes[i];
            if (!list_index)
                break;
            list_index--;
            if (list_info[list_index]->all_intfs_enabled ||
                list_info[list_index]->intfs.count(ingress_intf) ||
                list_info[list_index]->intfs.count(egress_intf))
            {
                if (TRUSTED_DO_NOT_BLOCK == (IPdecision)list_info[list_index]->list_type)
                    return DECISION_NULL;
                if (config.priority == (IPdecision)list_info[list_index]->list_type )
                {
                    listid = list_info[list_index]->list_id;
                    return  ((IPdecision)list_info[list_index]->list_type);
                }
                else if ( decision < list_info[list_index]->list_type)
                {
                    decision = (IPdecision)list_info[list_index]->list_type;
                    listid = list_info[list_index]->list_id;
                }
            }
        }

        if (!rep_info->next)
            break;
        rep_info = (IPrepInfo*)(&base[rep_info->next]);
    }

    return decision;
}

static bool decision_per_layer(const ReputationConfig& config, ReputationData& data,
    uint32_t& iplist_id, uint32_t ingress_intf, uint32_t egress_intf, const ip::IpApi& ip_api,
    IPdecision* decision_final)
{
    const SfIp* ip = ip_api.get_src();
    IPrepInfo* result = reputation_lookup(config, data, ip);
    if (result)
    {
        IPdecision decision = get_reputation(config, data, result, iplist_id, ingress_intf,
            egress_intf);

        if (decision == BLOCKED)
            *decision_final = BLOCKED_SRC;
        else if (decision == MONITORED)
            *decision_final = MONITORED_SRC;
        else if (decision == TRUSTED)
            *decision_final = TRUSTED_SRC;
        else
            *decision_final = decision;

        if ( config.priority == decision)
            return true;
    }

    ip = ip_api.get_dst();
    result = reputation_lookup(config, data, ip);
    if (result)
    {
        IPdecision decision = get_reputation(config, data, result, iplist_id, ingress_intf,
            egress_intf);

        if (decision == BLOCKED)
            *decision_final = BLOCKED_DST;
        else if (decision == MONITORED)
            *decision_final = MONITORED_DST;
        else if (decision == TRUSTED)
            *decision_final = TRUSTED_DST;
        else
            *decision_final = decision;

        if ( config.priority == decision)
            return true;
    }

    return false;
}

static IPdecision reputation_decision(const ReputationConfig& config, ReputationData& data,
    Packet* p, uint32_t& iplist_id)
{
    IPdecision decision_final = DECISION_NULL;
    uint32_t ingress_intf = 0;
    uint32_t egress_intf = 0;

    if (p->pkth)
    {
        ingress_intf = p->pkth->ingress_index;
        if (p->pkth->egress_index < 0)
            egress_intf = ingress_intf;
        else
            egress_intf = p->pkth->egress_index;
    }

    if (config.nested_ip == INNER)
    {
        decision_per_layer(config, data, iplist_id, ingress_intf, egress_intf, p->ptrs.ip_api, &decision_final);
        return decision_final;
    }

    // For OUTER or ALL, save current layers, iterate, then restore layers as needed
    ip::IpApi blocked_api;
    ip::IpApi tmp_api = p->ptrs.ip_api;
    int8_t num_layer = 0;
    IpProtocol tmp_next = p->get_ip_proto_next();

    if (config.nested_ip == OUTER)
    {
        layer::set_outer_ip_api(p, p->ptrs.ip_api, p->ip_proto_next, num_layer);
        decision_per_layer(config, data, iplist_id, ingress_intf, egress_intf, p->ptrs.ip_api, &decision_final);
    }
    else if (config.nested_ip == ALL)
    {
        bool done = false;
        IPdecision decision_current = DECISION_NULL;

        while (!done and layer::set_outer_ip_api(p, p->ptrs.ip_api, p->ip_proto_next, num_layer))
        {
            done = decision_per_layer(config, data, iplist_id, ingress_intf, egress_intf, p->ptrs.ip_api,
                &decision_current);
            if (decision_current != DECISION_NULL)
            {
                if (decision_current == BLOCKED_SRC or decision_current == BLOCKED_DST)
                    blocked_api = p->ptrs.ip_api;
                decision_final = decision_current;
                decision_current = DECISION_NULL;
            }
        }
    }
    else
        assert(false); // Should never hit this

    if (decision_final != BLOCKED_SRC and decision_final != BLOCKED_DST)
        p->ptrs.ip_api = tmp_api;
    else if (config.nested_ip == ALL and p->ptrs.ip_api != blocked_api)
        p->ptrs.ip_api = blocked_api;

    p->ip_proto_next = tmp_next;
    return decision_final;
}

static IPdecision snort_reputation_aux_ip(const ReputationConfig& config, ReputationData& data,
    Packet* p, const SfIp* ip)
{
    IPdecision decision = DECISION_NULL;

    if (!data.ip_list)
        return decision;

    uint32_t ingress_intf = 0;
    uint32_t egress_intf = 0;

    if (p->pkth)
    {
        ingress_intf = p->pkth->ingress_index;
        if (p->pkth->egress_index < 0)
            egress_intf = ingress_intf;
        else
            egress_intf = p->pkth->egress_index;
    }

    IPrepInfo* result = reputation_lookup(config, data, ip);
    if (result)
    {
        uint32_t iplist_id;
        decision = get_reputation(config, data, result, iplist_id, ingress_intf,
            egress_intf);

        if (decision == BLOCKED)
        {
            // Prior to IPRep logging, IPS policy must be set to the default policy,
            set_ips_policy(get_default_ips_policy(SnortConfig::get_conf()));

            DetectionEngine::queue_event(GID_REPUTATION, REPUTATION_EVENT_BLOCKLIST_DST);
            ReputationVerdictEvent event(p, REP_VERDICT_BLOCKED, iplist_id, false);
            DataBus::publish(pub_id, ReputationEventIds::REP_MATCHED, event);
            p->active->drop_packet(p, true);

            // disable all preproc analysis and detection for this packet
            DetectionEngine::disable_all(p);
            p->active->block_session(p, true);
            p->active->set_drop_reason("reputation");
            reputationstats.aux_ip_blocked++;
            if (PacketTracer::is_active())
            {
                char ip_str[INET6_ADDRSTRLEN];
                sfip_ntop(ip, ip_str, sizeof(ip_str));
                PacketTracer::log("Reputation: packet blocked for auxiliary ip %s, drop\n",
                    ip_str);
            }
        }
        else if (decision == MONITORED)
        {
            DetectionEngine::queue_event(GID_REPUTATION, REPUTATION_EVENT_MONITOR_DST);
            ReputationVerdictEvent event(p, REP_VERDICT_MONITORED, iplist_id, false);
            DataBus::publish(pub_id, ReputationEventIds::REP_MATCHED, event);
            reputationstats.aux_ip_monitored++;
        }
        else if (decision == TRUSTED)
        {
            DetectionEngine::queue_event(GID_REPUTATION, REPUTATION_EVENT_ALLOWLIST_DST);
            ReputationVerdictEvent event(p, REP_VERDICT_TRUSTED, iplist_id, false);
            DataBus::publish(pub_id, ReputationEventIds::REP_MATCHED, event);
            p->active->trust_session(p, true);
            reputationstats.aux_ip_trusted++;
        }
    }
    return decision;
}

static const char* to_string(IPdecision ipd)
{
    switch (ipd)
    {
    case BLOCKED:
        return "blocked";
    case TRUSTED:
        return "trusted";
    case MONITORED:
        return "monitored";
    case BLOCKED_SRC:
        return "blocked_src";
    case BLOCKED_DST:
        return "blocked_dst";
    case TRUSTED_SRC:
        return "trusted_src";
    case TRUSTED_DST:
        return "trusted_dst";
    case TRUSTED_DO_NOT_BLOCK:
        return "trusted_do_not_block";
    case MONITORED_SRC:
        return "monitored_src";
    case MONITORED_DST:
        return "monitored_dst";
    case DECISION_NULL:
    case DECISION_MAX:
    default:
        return "";
    }
}

static void populate_trace_data(IPdecision& decision, Packet* p, uint32_t iplist_id)
{
    char addr[INET6_ADDRSTRLEN];
    const SfIp* ip = nullptr;

    if (BLOCKED_SRC == decision or MONITORED_SRC == decision or TRUSTED_SRC == decision)
    {
        ip = p->ptrs.ip_api.get_src();
    }
    else if (BLOCKED_DST == decision or MONITORED_DST == decision or TRUSTED_DST == decision)
    {
        ip = p->ptrs.ip_api.get_dst();
    }

    sfip_ntop(ip, addr, sizeof(addr));

    PacketTracer::daq_log("SI-IP+%" PRId64"+%s list id %u+Matched ip %s, action %s$",
        TO_NSECS(pt_timer->get()),
        (TRUSTED_SRC == decision or TRUSTED_DST == decision)?"Do_not_block":"Block",
        iplist_id, addr, to_string(decision));
}

static void snort_reputation(const ReputationConfig& config, ReputationData& data, Packet* p)
{
    IPdecision decision;

    if (!data.ip_list)
        return;

    uint32_t iplist_id;
    decision = reputation_decision(config, data, p, iplist_id);
    Active* act = p->active;

    if (BLOCKED_SRC == decision or BLOCKED_DST == decision)
    {
        unsigned blocklist_event = (BLOCKED_SRC == decision) ?
            REPUTATION_EVENT_BLOCKLIST_SRC : REPUTATION_EVENT_BLOCKLIST_DST;

        DetectionEngine::queue_event(GID_REPUTATION, blocklist_event);
        ReputationVerdictEvent event(p, REP_VERDICT_BLOCKED, iplist_id, BLOCKED_SRC == decision);
        DataBus::publish(pub_id, ReputationEventIds::REP_MATCHED, event);
        act->drop_packet(p, true);

        // disable all preproc analysis and detection for this packet
        DetectionEngine::disable_all(p);
        act->block_session(p, true);
        if (p->flow)
            p->flow->set_state(Flow::FlowState::BLOCK);
        act->set_drop_reason("reputation");
        reputationstats.blocked++;
        if (PacketTracer::is_active())
            PacketTracer::log("Reputation: packet blocked, drop\n");

        if (PacketTracer::is_daq_activated())
            populate_trace_data(decision, p, iplist_id);

        return;
    }

    if ( p->flow and p->flow->reload_id > 0 )
    {
        const auto& aux_ip_list =  p->flow->stash->get_aux_ip_list();
        for ( const auto& ip : aux_ip_list )
        {
            if ( BLOCKED == snort_reputation_aux_ip(config, data, p, &ip) )
                return;
        }
    }

    if (DECISION_NULL == decision)
    {
        return;
    }

    if (MONITORED_SRC == decision or MONITORED_DST == decision)
    {
        unsigned monitor_event = (MONITORED_SRC == decision) ?
            REPUTATION_EVENT_MONITOR_SRC : REPUTATION_EVENT_MONITOR_DST;

        DetectionEngine::queue_event(GID_REPUTATION, monitor_event);
        ReputationVerdictEvent event(p, REP_VERDICT_MONITORED, iplist_id, MONITORED_SRC == decision);
        DataBus::publish(pub_id, ReputationEventIds::REP_MATCHED, event);
        reputationstats.monitored++;
    }

    else if (TRUSTED_SRC == decision or TRUSTED_DST == decision)
    {
        unsigned allowlist_event = (TRUSTED_SRC == decision) ?
            REPUTATION_EVENT_ALLOWLIST_SRC : REPUTATION_EVENT_ALLOWLIST_DST;

        DetectionEngine::queue_event(GID_REPUTATION, allowlist_event);
        ReputationVerdictEvent event(p, REP_VERDICT_TRUSTED, iplist_id, TRUSTED_SRC == decision);
        DataBus::publish(pub_id, ReputationEventIds::REP_MATCHED, event);
        act->trust_session(p, true);
        reputationstats.trusted++;
    }

    if (PacketTracer::is_daq_activated())
        populate_trace_data(decision, p, iplist_id);
}

static const char* to_string(NestedIP nip)
{
    switch (nip)
    {
    case INNER:
        return "inner";
    case OUTER:
        return "outer";
    case ALL:
        return "all";
    }

    return "";
}

static const char* to_string(AllowAction aa)
{
    switch (aa)
    {
    case DO_NOT_BLOCK:
        return "do_not_block";
    case TRUST:
        return "trust";
    }

    return "";
}

class IpRepHandler : public DataHandler
{
public:
    explicit IpRepHandler(Reputation& inspector)
        : DataHandler(REPUTATION_NAME), inspector(inspector)
    { order = 5; }
    void handle(DataEvent&, Flow*) override;

private:
    Reputation& inspector;
};

void IpRepHandler::handle(DataEvent& event, Flow*)
{
    Profile profile(reputation_perf_stats);
    Packet* p = const_cast<Packet*>(event.get_packet());
    assert(p);
    if (!p->has_ip())
        return;

    if (PacketTracer::is_daq_activated())
        PacketTracer::pt_timer_start();

    ReputationData* data = static_cast<ReputationData*>(inspector.get_thread_specific_data());
    assert(data);
    snort_reputation(inspector.get_config(), *data, p);
    ++reputationstats.packets;
}

class AuxiliaryIpRepHandler : public DataHandler
{
public:
    explicit AuxiliaryIpRepHandler(Reputation& inspector)
        : DataHandler(REPUTATION_NAME), inspector(inspector)
    { }
    void handle(DataEvent&, Flow*) override;

private:
    Reputation& inspector;
};

void AuxiliaryIpRepHandler::handle(DataEvent& event, Flow*)
{
    Profile profile(reputation_perf_stats);
    ReputationData* data = static_cast<ReputationData*>(inspector.get_thread_specific_data());
    assert(data);
    snort_reputation_aux_ip(inspector.get_config(), *data, DetectionEngine::get_current_packet(),
        static_cast<AuxiliaryIpEvent*>(&event)->get_ip());
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

ReputationData::~ReputationData()
{
    if (reputation_segment)
        snort_free(reputation_segment);

    for (auto& file : list_files)
        delete file;
}

Reputation::Reputation(ReputationConfig* pc) : config(*pc)
{ rep_data = load_data(); }

Reputation::~Reputation()
{ delete rep_data; }

ReputationData* Reputation::load_data()
{
    ReputationData* data = new ReputationData();
    if (!config.list_dir.empty())
        ReputationParser::read_manifest(MANIFEST_FILENAME, config, *data);

    ReputationParser::add_block_allow_List(config, *data);
    ReputationParser::estimate_num_entries(*data);
    if (0 >= data->num_entries)
    {
        ParseWarning(WARN_CONF,
            "reputation: can't find any allowlist/blocklist entries; disabled.");
    }
    else
    {
        ReputationParser parser;
        parser.ip_list_init(data->num_entries + 1, config, *data);
        reputationstats.memory_allocated = parser.get_usage();
    }

    return data;
}

void Reputation::swap_thread_data(ReputationData* data)
{ set_thread_specific_data(data); }

void Reputation::swap_data(ReputationData* data)
{
    delete rep_data;
    rep_data = data;
}

void Reputation::tinit()
{ set_thread_specific_data(rep_data); }

void Reputation::tterm()
{ set_thread_specific_data(nullptr); }

void Reputation::show(const SnortConfig*) const
{
    ConfigLogger::log_value("blocklist", config.blocklist_path.c_str());
    ConfigLogger::log_value("list_dir", config.list_dir.c_str());
    ConfigLogger::log_value("memcap", config.memcap);
    ConfigLogger::log_value("nested_ip", to_string(config.nested_ip));
    ConfigLogger::log_value("priority", to_string(config.priority));
    ConfigLogger::log_flag("scan_local", config.scanlocal);
    ConfigLogger::log_value("allow (action)", to_string(config.allow_action));
    ConfigLogger::log_value("allowlist", config.allowlist_path.c_str());
}

bool Reputation::configure(SnortConfig*)
{
    DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_SETUP, new IpRepHandler(*this));
    DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_RELOADED, new IpRepHandler(*this));
    DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::AUXILIARY_IP, new AuxiliaryIpRepHandler(*this));
    DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::PKT_WITHOUT_FLOW, new IpRepHandler(*this));

    pub_id = DataBus::get_id(reputation_pub_key);
    return true;
}

void Reputation::install_reload_handler(SnortConfig* sc)
{ sc->register_reload_handler(new ReputationReloadSwapper(*this)); }

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ReputationModule; }

static void mod_dtor(Module* m)
{ delete m; }


static Inspector* reputation_ctor(Module* m)
{
    ReputationModule* mod = (ReputationModule*)m;
    ReputationConfig* conf = mod->get_data();
    return conf ? new Reputation(conf) : nullptr;
}

static void reputation_dtor(Inspector* p)
{
    delete p;
}

const InspectApi reputation_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        REPUTATION_NAME,
        REPUTATION_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__ANY_IP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    reputation_ctor,
    reputation_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &reputation_api.base,
    nullptr
};
#else
const BaseApi* nin_reputation = &reputation_api.base;
#endif
