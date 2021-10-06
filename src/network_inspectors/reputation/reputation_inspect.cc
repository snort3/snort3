//--------------------------------------------------------------------------
// Copyright (C) 2014-2021 Cisco and/or its affiliates. All rights reserved.
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
#include "network_inspectors/packet_tracer/packet_tracer.h"
#include "packet_io/active.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "pub_sub/auxiliary_ip_event.h"

#include "reputation_parse.h"

using namespace snort;

THREAD_LOCAL ProfileStats reputation_perf_stats;
THREAD_LOCAL ReputationStats reputationstats;

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

const char* NestedIPKeyword[] =
{
    "inner",
    "outer",
    "all",
    nullptr
};

const char* AllowActionOption[] =
{
    "do_not_block",
    "trust",
    nullptr
};

/*
 * Function prototype(s)
 */
static void snort_reputation(ReputationConfig* GlobalConf, Packet* p);
static void populate_trace_data(IPdecision& decision, Packet* p);

static inline IPrepInfo* reputation_lookup(ReputationConfig* config, const SfIp* ip)
{
    IPrepInfo* result;

    if (!config->scanlocal)
    {
        if (ip->is_private() )
        {
            return nullptr;
        }
    }

    result = (IPrepInfo*)sfrt_flat_dir8x_lookup(ip, config->ip_list);

    return (result);
}

static inline IPdecision get_reputation(ReputationConfig* config, IPrepInfo* rep_info,
    uint32_t* listid, uint32_t ingress_intf, uint32_t egress_intf)
{
    IPdecision decision = DECISION_NULL;

    /*Walk through the IPrepInfo lists*/
    uint8_t* base = (uint8_t*)config->ip_list;
    ListFiles& list_info =  config->list_files;

    while (rep_info)
    {
        int i;
        for (i = 0; i < NUM_INDEX_PER_ENTRY; i++)
        {
            int list_index = rep_info->list_indexes[i];
            if (!list_index)
                break;
            list_index--;
            if (list_info[list_index]->all_intfs_enabled ||
                list_info[list_index]->intfs.count(ingress_intf) ||
                list_info[list_index]->intfs.count(egress_intf))
            {
                if (TRUSTED_DO_NOT_BLOCK == (IPdecision)list_info[list_index]->list_type)
                    return DECISION_NULL;
                if (config->priority == (IPdecision)list_info[list_index]->list_type )
                {
                    *listid = list_info[list_index]->list_id;
                    return  ((IPdecision)list_info[list_index]->list_type);
                }
                else if ( decision < list_info[list_index]->list_type)
                {
                    decision = (IPdecision)list_info[list_index]->list_type;
                    *listid = list_info[list_index]->list_id;
                }
            }
        }

        if (!rep_info->next)
            break;
        rep_info = (IPrepInfo*)(&base[rep_info->next]);
    }

    return decision;
}

static bool decision_per_layer(ReputationConfig* config, Packet* p,
    uint32_t ingress_intf, uint32_t egress_intf, const ip::IpApi& ip_api, IPdecision* decision_final)
{
    const SfIp* ip;
    IPdecision decision;
    IPrepInfo* result;

    ip = ip_api.get_src();
    result = reputation_lookup(config, ip);
    if (result)
    {
        decision = get_reputation(config, result, &p->iplist_id, ingress_intf, egress_intf);

        if (decision == BLOCKED)
            *decision_final = BLOCKED_SRC;
        else if (decision == MONITORED)
            *decision_final = MONITORED_SRC;
        else if (decision == TRUSTED)
            *decision_final = TRUSTED_SRC;
        else
            *decision_final = decision;

        if ( config->priority == decision)
            return true;
    }

    ip = ip_api.get_dst();
    result = reputation_lookup(config, ip);
    if (result)
    {
        decision = get_reputation(config, result, &p->iplist_id, ingress_intf, egress_intf);

        if (decision == BLOCKED)
            *decision_final = BLOCKED_DST;
        else if (decision == MONITORED)
            *decision_final = MONITORED_DST;
        else if (decision == TRUSTED)
            *decision_final = TRUSTED_DST;
        else
            *decision_final = decision;

        if ( config->priority == decision)
            return true;
    }

    return false;
}

static IPdecision reputation_decision(ReputationConfig* config, Packet* p)
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

    if (config->nested_ip == INNER)
    {
        decision_per_layer(config, p, ingress_intf, egress_intf, p->ptrs.ip_api, &decision_final);
        return decision_final;
    }

    // For OUTER or ALL, save current layers, iterate, then restore layers as needed
    ip::IpApi blocked_api;
    ip::IpApi tmp_api = p->ptrs.ip_api;
    int8_t num_layer = 0;
    IpProtocol tmp_next = p->get_ip_proto_next();

    if (config->nested_ip == OUTER)
    {
        layer::set_outer_ip_api(p, p->ptrs.ip_api, p->ip_proto_next, num_layer);
        decision_per_layer(config, p, ingress_intf, egress_intf, p->ptrs.ip_api, &decision_final);
    }
    else if (config->nested_ip == ALL)
    {
        bool done = false;
        IPdecision decision_current = DECISION_NULL;

        while (!done and layer::set_outer_ip_api(p, p->ptrs.ip_api, p->ip_proto_next, num_layer))
        {
            done = decision_per_layer(config, p, ingress_intf, egress_intf, p->ptrs.ip_api,
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
    else if (config->nested_ip == ALL and p->ptrs.ip_api != blocked_api)
        p->ptrs.ip_api = blocked_api;

    p->ip_proto_next = tmp_next;
    return decision_final;
}

static IPdecision snort_reputation_aux_ip(ReputationConfig* config, Packet* p, const SfIp* ip)
{
    IPdecision decision = DECISION_NULL;

    if (!config->ip_list)
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

    IPrepInfo* result = reputation_lookup(config, ip);
    if (result)
    {
        decision = get_reputation(config, result, &p->iplist_id, ingress_intf,
            egress_intf);

        if (decision == BLOCKED)
        {
            if (p->flow)
                p->flow->flags.reputation_blocklist = true;

            // Prior to IPRep logging, IPS policy must be set to the default policy,
            set_ips_policy(SnortConfig::get_conf(), 0);

            DetectionEngine::queue_event(GID_REPUTATION, REPUTATION_EVENT_BLOCKLIST_DST);
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
            if (p->flow)
            {
                p->flow->flags.reputation_monitor = true;
                p->flow->iplist_monitor_id = p->iplist_id;
            }

            DetectionEngine::queue_event(GID_REPUTATION, REPUTATION_EVENT_MONITOR_DST);
            reputationstats.aux_ip_monitored++;
        }
        else if (decision == TRUSTED)
        {
            if (p->flow)
                p->flow->flags.reputation_allowlist = true;

            DetectionEngine::queue_event(GID_REPUTATION, REPUTATION_EVENT_ALLOWLIST_DST);
            p->active->trust_session(p, true);
            reputationstats.aux_ip_trusted++;
        }
    }
    return decision;
}

static void snort_reputation(ReputationConfig* config, Packet* p)
{
    IPdecision decision;

    if (!config->ip_list)
        return;

    decision = reputation_decision(config, p);
    Active* act = p->active;

    if (BLOCKED_SRC == decision or BLOCKED_DST == decision)
    {
        unsigned blocklist_event = (BLOCKED_SRC == decision) ?
            REPUTATION_EVENT_BLOCKLIST_SRC : REPUTATION_EVENT_BLOCKLIST_DST;

        if (p->flow)
        {
            p->flow->flags.reputation_blocklist = true;
            p->flow->flags.reputation_src_dest = (BLOCKED_SRC == decision);
        }

        DetectionEngine::queue_event(GID_REPUTATION, blocklist_event);
        act->drop_packet(p, true);

        // disable all preproc analysis and detection for this packet
        DetectionEngine::disable_all(p);
        act->block_session(p, true);
        act->set_drop_reason("reputation");
        reputationstats.blocked++;
        if (PacketTracer::is_active())
            PacketTracer::log("Reputation: packet blocked, drop\n");

        if (PacketTracer::is_daq_activated())
            populate_trace_data(decision, p);

        return;
    }

    else if ( p->flow and p->flow->reload_id > 0 )
    {
        const auto& aux_ip_list =  p->flow->stash->get_aux_ip_list();
        for ( const auto& ip : aux_ip_list )
        {
            if ( BLOCKED == snort_reputation_aux_ip(config, p, &ip) )
                return;
        }
    }

    if (DECISION_NULL == decision)
    {
        return;
    }

    else if (MONITORED_SRC == decision or MONITORED_DST == decision)
    {
        unsigned monitor_event = (MONITORED_SRC == decision) ?
            REPUTATION_EVENT_MONITOR_SRC : REPUTATION_EVENT_MONITOR_DST;

        if (p->flow)
        {
            p->flow->flags.reputation_monitor = true;
            p->flow->flags.reputation_src_dest = (MONITORED_SRC == decision);
        }

        DetectionEngine::queue_event(GID_REPUTATION, monitor_event);
        reputationstats.monitored++;
    }

    else if (TRUSTED_SRC == decision or TRUSTED_DST == decision)
    {
        unsigned allowlist_event = (TRUSTED_SRC == decision) ?
            REPUTATION_EVENT_ALLOWLIST_SRC : REPUTATION_EVENT_ALLOWLIST_DST;

        if (p->flow)
        {
            p->flow->flags.reputation_allowlist = true;
            p->flow->flags.reputation_src_dest = (TRUSTED_SRC == decision);
        }

        DetectionEngine::queue_event(GID_REPUTATION, allowlist_event);
        act->trust_session(p, true);
        reputationstats.trusted++;
    }

    if (PacketTracer::is_daq_activated())
        populate_trace_data(decision, p);
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

static void populate_trace_data(IPdecision& decision, Packet* p)
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
        p->iplist_id, addr, to_string(decision));
}

class AuxiliaryIpRepHandler : public DataHandler
{
public:
    AuxiliaryIpRepHandler(ReputationConfig& rc) : DataHandler(REPUTATION_NAME), conf(rc) { }
    void handle(DataEvent&, Flow*) override;

private:
    ReputationConfig& conf;
};

void AuxiliaryIpRepHandler::handle(DataEvent& event, Flow*)
{
    Profile profile(reputation_perf_stats);
    snort_reputation_aux_ip(&conf, DetectionEngine::get_current_packet(),
        static_cast<AuxiliaryIpEvent*>(&event)->get_ip());
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

Reputation::Reputation(ReputationConfig* pc)
{
    config = *pc;
    ReputationConfig* conf = &config;
    if (!config.list_dir.empty())
        read_manifest(MANIFEST_FILENAME, conf);

    add_block_allow_List(conf);
    estimate_num_entries(conf);
    if (conf->num_entries <= 0)
    {
        ParseWarning(WARN_CONF,
            "reputation: can't find any allowlist/blocklist entries; disabled.");
        return;
    }

    ip_list_init(conf->num_entries + 1, conf);
    reputationstats.memory_allocated = sfrt_flat_usage(conf->ip_list);
}

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

void Reputation::eval(Packet* p)
{
    Profile profile(reputation_perf_stats);

    // precondition - what we registered for
    assert(p->has_ip());

    if (p->is_rebuilt())
        return;

    if (PacketTracer::is_daq_activated())
        PacketTracer::pt_timer_start();

    snort_reputation(&config, p);
    ++reputationstats.packets;
}

bool Reputation::configure(SnortConfig* sc)
{
    DataBus::subscribe_global( AUXILIARY_IP_EVENT, new AuxiliaryIpRepHandler(config), sc );
    return true;
}

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
    IT_FIRST,
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
