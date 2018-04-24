//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
#include "packet_io/active.h"
#include "profiler/profiler.h"

#include "reputation_module.h"

using namespace snort;

THREAD_LOCAL ProfileStats reputation_perf_stats;
THREAD_LOCAL ReputationStats reputationstats;

const PegInfo reputation_peg_names[] =
{
{ CountType::SUM, "packets", "total packets processed" },
{ CountType::SUM, "blacklisted", "number of packets blacklisted" },
{ CountType::SUM, "whitelisted", "number of packets whitelisted" },
{ CountType::SUM, "monitored", "number of packets monitored" },
{ CountType::SUM, "memory_allocated", "total memory allocated" },

{ CountType::END, nullptr, nullptr }
};

const char* NestedIPKeyword[] =
{
    "inner",
    "outer",
    "all",
    nullptr
};

const char* WhiteActionOption[] =
{
    "unblack",
    "trust",
    nullptr
};

/*
 * Function prototype(s)
 */
static void snort_reputation(ReputationConfig* GlobalConf, Packet* p);

unsigned ReputationFlowData::inspector_id = 0;

static ReputationData* set_new_reputation_data(Flow* flow)
{
    ReputationFlowData* fd = new ReputationFlowData;
    flow->set_flow_data(fd);
    return &fd->session;
}

static ReputationData* get_session_data(Flow* flow)
{
    ReputationFlowData* fd = (ReputationFlowData*)flow->get_flow_data(
        ReputationFlowData::inspector_id);

    return fd ? &fd->session : nullptr;
}

static bool is_reputation_disabled(Flow* flow)
{
    ReputationData* data;

    if (!flow)
        return false;

    data = get_session_data(flow);

    if (!data)
        set_new_reputation_data(flow);

    return data ? data->disabled : false;
}

static void disable_reputation(Flow* flow)
{
    ReputationData* data;

    if (!flow)
        return;

    data = get_session_data(flow);

    if (data)
        data->disabled = true;
}

static void print_iplist_stats(ReputationConfig* config)
{
    /*Print out the summary*/
    LogMessage("    Reputation total memory usage: " STDu64 " bytes\n",
        reputationstats.memory_allocated);
    config->num_entries = sfrt_flat_num_entries(config->ip_list);
    LogMessage("    Reputation total entries loaded: %u, invalid: %lu, re-defined: %lu\n",
        config->num_entries,total_invalids,total_duplicates);
}

static void print_reputation_conf(ReputationConfig* config)
{
    assert(config);

    print_iplist_stats(config);

    LogMessage("    Memcap: %d %s \n",
        config->memcap,
        config->memcap == 500 ? "(Default) M bytes" : "M bytes");
    LogMessage("    Scan local network: %s\n",
        config->scanlocal ? "ENABLED" : "DISABLED (Default)");
    LogMessage("    Reputation priority:  %s \n",
        config->priority ==  WHITELISTED_TRUST ?
        "whitelist (Default)" : "blacklist");
    LogMessage("    Nested IP: %s %s \n",
        NestedIPKeyword[config->nested_ip],
        config->nested_ip ==  INNER ? "(Default)" : "");
    LogMessage("    White action: %s %s \n",
        WhiteActionOption[config->white_action],
        config->white_action ==  UNBLACK ? "(Default)" : "");
    if (config->blacklist_path)
        LogMessage("    Blacklist File Path: %s\n", config->blacklist_path);

    if (config->whitelist_path)
        LogMessage("    Whitelist File Path: %s\n", config->whitelist_path);

    LogMessage("\n");
}

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
    uint32_t* listid, uint32_t ingress_zone, uint32_t egress_zone)
{
    IPdecision decision = DECISION_NULL;
    uint8_t* base;
    ListInfo* list_info;

    /*Walk through the IPrepInfo lists*/
    base = (uint8_t*)config->ip_list;
    list_info =  (ListInfo*)(&base[config->ip_list->list_info]);

    while (rep_info)
    {
        int i;
        for (i = 0; i < NUM_INDEX_PER_ENTRY; i++)
        {
            int list_index = rep_info->list_indexes[i];
            if (!list_index)
                break;
            list_index--;
            if (list_info[list_index].zones[ingress_zone] || list_info[list_index].zones[egress_zone])
            {
                if (WHITELISTED_UNBLACK == (IPdecision)list_info[list_index].list_type)
                    return DECISION_NULL;
                if (config->priority == (IPdecision)list_info[list_index].list_type )
                {
                    *listid = list_info[list_index].list_id;
                    return  ((IPdecision)list_info[list_index].list_type);
                }
                else if ( decision < list_info[list_index].list_type)
                {
                    decision = (IPdecision)list_info[list_index].list_type;
                    *listid = list_info[list_index].list_id;
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
    uint32_t ingressZone, uint32_t egressZone, const ip::IpApi& ip_api, IPdecision* decision_final)
{
    const SfIp* ip;
    IPdecision decision;
    IPrepInfo* result;

    ip = ip_api.get_src();
    result = reputation_lookup(config, ip);
    if (result)
    {
        decision = get_reputation(config, result, &p->iplist_id, ingressZone, egressZone);

        *decision_final = decision;
        if ( config->priority == decision)
            return true;
    }

    ip = ip_api.get_dst();
    result = reputation_lookup(config, ip);
    if (result)
    {
        decision = get_reputation(config, result, &p->iplist_id, ingressZone, egressZone);

        *decision_final = decision;
        if ( config->priority == decision)
            return true;
    }

    return false;
}

static IPdecision reputation_decision(ReputationConfig* config, Packet* p)
{
    IPdecision decision_final = DECISION_NULL;
    uint32_t ingress_zone = 0;
    uint32_t egress_zone = 0;

    if (p->pkth)
    {
        ingress_zone = p->pkth->ingress_group;
        if (p->pkth->egress_index < 0)
            egress_zone = ingress_zone;
        else
            egress_zone = p->pkth->egress_group;

        /*Make sure zone ids are in the support range*/
        if (ingress_zone >= MAX_NUM_ZONES)
            ingress_zone = 0;
        if (egress_zone >= MAX_NUM_ZONES)
            egress_zone = 0;
    }

    ip::IpApi tmp_api = p->ptrs.ip_api;
    int8_t num_layer = 0;
    IpProtocol tmp_next = p->get_ip_proto_next();
    bool outer_layer_only = (config->nested_ip == OUTER) ? true : false;
    bool outer_layer = false;

    while (layer::set_outer_ip_api(p, p->ptrs.ip_api, p->ip_proto_next, num_layer) &&
        tmp_api != p->ptrs.ip_api)
    {
        outer_layer = true;

        if (decision_per_layer(config, p, ingress_zone, egress_zone,p->ptrs.ip_api,
                &decision_final))
            return decision_final;

        if (outer_layer_only)
        {
            p->ip_proto_next = tmp_next;
            p->ptrs.ip_api = tmp_api;
            return decision_final;
        }
    }

    p->ip_proto_next = tmp_next;
    p->ptrs.ip_api = tmp_api;

    /*Check INNER IP, when configured or only one layer*/
    if (!outer_layer || (config->nested_ip == INNER) || (config->nested_ip == ALL))
    {
        decision_per_layer(config, p, ingress_zone, egress_zone, p->ptrs.ip_api,
            &decision_final);
    }

    return (decision_final);
}

static void snort_reputation(ReputationConfig* config, Packet* p)
{
    IPdecision decision;

    if (!config->ip_list)
        return;

    decision = reputation_decision(config, p);

    if (DECISION_NULL == decision)
        return;

    else if (BLACKLISTED == decision)
    {
        DetectionEngine::queue_event(GID_REPUTATION, REPUTATION_EVENT_BLACKLIST);
        Active::drop_packet(p, true);
        // disable all preproc analysis and detection for this packet
        DetectionEngine::disable_all(p);
        Active::block_session(p, true);
        reputationstats.blacklisted++;
    }
    else if (MONITORED == decision)
    {
        DetectionEngine::queue_event(GID_REPUTATION, REPUTATION_EVENT_MONITOR);
        reputationstats.monitored++;
    }
    else if (WHITELISTED_TRUST == decision)
    {
        DetectionEngine::queue_event(GID_REPUTATION, REPUTATION_EVENT_WHITELIST);
        p->packet_flags |= PKT_IGNORE;
        DetectionEngine::disable_all(p);
        Active::allow_session(p);
        reputationstats.whitelisted++;
    }
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Reputation : public Inspector
{
public:
    Reputation(ReputationConfig*);
    ~Reputation() override;

    void show(SnortConfig*) override;
    void eval(Packet*) override;

private:
    ReputationConfig* config;
};

Reputation::Reputation(ReputationConfig* pc)
{
    config = pc;
    reputationstats.memory_allocated = sfrt_flat_usage(config->ip_list);
}

Reputation::~Reputation()
{
    if ( config )
    {
        delete config;
    }
}

void Reputation::show(SnortConfig*)
{
    print_reputation_conf(config);
}

void Reputation::eval(Packet* p)
{
    Profile profile(reputation_perf_stats);

    // precondition - what we registered for
    assert(p->has_ip());

    if (!p->is_rebuilt() && !is_reputation_disabled(p->flow))
    {
        snort_reputation(config, p);
        disable_reputation(p->flow);
        ++reputationstats.packets;
    }
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ReputationModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void reputation_init()
{
    ReputationFlowData::init();
}

static Inspector* reputation_ctor(Module* m)
{
    ReputationModule* mod = (ReputationModule*)m;
    return new Reputation(mod->get_data());
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
    IT_NETWORK,
    PROTO_BIT__ANY_IP,
    nullptr, // buffers
    nullptr, // service
    reputation_init, // pinit
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

