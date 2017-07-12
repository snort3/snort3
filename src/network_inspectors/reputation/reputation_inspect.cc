//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

THREAD_LOCAL ProfileStats reputationPerfStats;
THREAD_LOCAL ReputationStats reputationstats;

const PegInfo reputation_peg_names[] =
{
    { "packets", "total packets processed" },
    { "blacklisted", "number of packets blacklisted" },
    { "whitelisted", "number of packets whitelisted" },
    { "monitored", "number of packets monitored" },
    { "memory_allocated", "total memory allocated" },

    { nullptr, nullptr }
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

static ReputationData* SetNewReputationData(Flow* flow)
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

static bool IsReputationDisabled(Flow* flow)
{
    ReputationData* data;

    if (!flow)
        return false;

    data = get_session_data(flow);

    if (!data)
        SetNewReputationData(flow);

    return data ? data->disabled : false;
}

static void DisableReputation(Flow* flow)
{
    ReputationData* data;

    if (!flow)
        return;

    data = get_session_data(flow);

    if (data)
        data->disabled = true;
}

static void PrintIPlistStats(ReputationConfig* config)
{
    /*Print out the summary*/
    LogMessage("    Reputation total memory usage: " STDu64 " bytes\n",
        reputationstats.memory_allocated);
    config->numEntries = sfrt_flat_num_entries(config->iplist);
    LogMessage("    Reputation total entries loaded: %u, invalid: %lu, re-defined: %lu\n",
        config->numEntries,total_invalids,total_duplicates);
}

static void PrintReputationConf(ReputationConfig* config)
{
    assert(config);

    PrintIPlistStats(config);

    LogMessage("    Memcap: %d %s \n",
        config->memcap,
        config->memcap == 500 ? "(Default) M bytes" : "M bytes");
    LogMessage("    Scan local network: %s\n",
        config->scanlocal ? "ENABLED" : "DISABLED (Default)");
    LogMessage("    Reputation priority:  %s \n",
        config->priority ==  WHITELISTED_TRUST ?
        "whitelist (Default)" : "blacklist");
    LogMessage("    Nested IP: %s %s \n",
        NestedIPKeyword[config->nestedIP],
        config->nestedIP ==  INNER ? "(Default)" : "");
    LogMessage("    White action: %s %s \n",
        WhiteActionOption[config->whiteAction],
        config->whiteAction ==  UNBLACK ? "(Default)" : "");
    if (config->blacklist_path)
        LogMessage("    Blacklist File Path: %s\n", config->blacklist_path);

    if (config->whitelist_path)
        LogMessage("    Whitelist File Path: %s\n", config->whitelist_path);

    LogMessage("\n");
}

static inline IPrepInfo* ReputationLookup(ReputationConfig* config, const SfIp* ip)
{
    IPrepInfo* result;

    DEBUG_WRAP(DebugFormat(DEBUG_REPUTATION, "Lookup address: %s \n", ip->ntoa() ); );
    if (!config->scanlocal)
    {
        if (ip->is_private() )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "Private address\n"); );
            return nullptr;
        }
    }

    result = (IPrepInfo*)sfrt_flat_dir8x_lookup(ip, config->iplist);

    return (result);
}

static inline IPdecision GetReputation(ReputationConfig* config, IPrepInfo* repInfo,
    uint32_t* listid)
{
    IPdecision decision = DECISION_NULL;
    uint8_t* base;
    ListInfo* listInfo;

    /*Walk through the IPrepInfo lists*/
    base = (uint8_t*)config->iplist;
    listInfo =  (ListInfo*)(&base[config->iplist->list_info]);

    while (repInfo)
    {
        int i;
        for (i = 0; i < NUM_INDEX_PER_ENTRY; i++)
        {
            int list_index = repInfo->listIndexes[i];
            if (!list_index)
                break;
            list_index--;
            if (WHITELISTED_UNBLACK == (IPdecision)listInfo[list_index].listType)
                return DECISION_NULL;
            if (config->priority == (IPdecision)listInfo[list_index].listType )
            {
                *listid = listInfo[list_index].listId;
                return  ((IPdecision)listInfo[list_index].listType);
            }
            else if ( decision < listInfo[list_index].listType)
            {
                decision = (IPdecision)listInfo[list_index].listType;
                *listid = listInfo[list_index].listId;
            }
        }

        if (!repInfo->next)
            break;
        repInfo = (IPrepInfo*)(&base[repInfo->next]);
    }

    return decision;
}

static bool ReputationDecisionPerLayer(ReputationConfig* config, Packet* p,
        const ip::IpApi& ip_api, IPdecision* decision_final)
{
    const SfIp* ip;
    IPdecision decision;
    IPrepInfo* result;

    ip = ip_api.get_src();
    result = ReputationLookup(config, ip);
    if (result)
    {
        decision = GetReputation(config, result, &p->iplist_id);

        *decision_final = decision;
        if ( config->priority == decision)
            return true;
    }

    ip = ip_api.get_dst();
    result = ReputationLookup(config, ip);
    if (result)
    {
        decision = GetReputation(config, result, &p->iplist_id);

        *decision_final = decision;
        if ( config->priority == decision)
            return true;
    }

    return false;
}

static IPdecision ReputationDecision(ReputationConfig* config, Packet* p)
{
    IPdecision decision_final = DECISION_NULL;

    ip::IpApi tmp_api = p->ptrs.ip_api;
    int8_t num_layer = 0;
    IpProtocol tmp_next = p->get_ip_proto_next();
    bool outer_layer_only = (config->nestedIP == OUTER)? true: false;
    bool outer_layer = false;

    while (layer::set_outer_ip_api(p, p->ptrs.ip_api, p->ip_proto_next, num_layer) &&
                tmp_api != p->ptrs.ip_api)
    {
        outer_layer = true;

        if(ReputationDecisionPerLayer(config, p, p->ptrs.ip_api, &decision_final))
            return decision_final;

        if(outer_layer_only)
        {
            p->ip_proto_next = tmp_next;
            p->ptrs.ip_api = tmp_api;
            return decision_final;
        }
    }

    p->ip_proto_next = tmp_next;
    p->ptrs.ip_api = tmp_api;

    /*Check INNER IP, when configured or only one layer*/
    if (!outer_layer || (config->nestedIP == INNER) || (config->nestedIP == ALL))
    {
        ReputationDecisionPerLayer(config, p, p->ptrs.ip_api, &decision_final);
    }

    return (decision_final);
}

static void snort_reputation(ReputationConfig* config, Packet* p)
{
    IPdecision decision;

    if (!config->iplist)
        return;

    decision = ReputationDecision(config, p);

    if (DECISION_NULL == decision)
        return;

    else if (BLACKLISTED == decision)
    {
        DetectionEngine::queue_event(GID_REPUTATION, REPUTATION_EVENT_BLACKLIST);
        Active::drop_packet(p, true);
        // disable all preproc analysis and detection for this packet
        DetectionEngine::disable_all(p);
        p->disable_inspect = true;
        if (p->flow)
        {
            p->flow->set_state(Flow::FlowState::BLOCK);
            p->flow->disable_inspection();
        }

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
        p->disable_inspect = true;
        if (p->flow)
        {
            p->flow->set_state(Flow::FlowState::ALLOW);
            p->flow->disable_inspection();
        }
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
    ~Reputation();

    void show(SnortConfig*) override;
    void eval(Packet*) override;

private:
    ReputationConfig* config;
};

Reputation::Reputation(ReputationConfig* pc)
{
    config = pc;
    reputationstats.memory_allocated = sfrt_flat_usage(config->iplist);
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
    PrintReputationConf(config);
}

void Reputation::eval(Packet* p)
{
    Profile profile(reputationPerfStats);

    // precondition - what we registered for
    assert(p->has_ip());

    if (!p->is_rebuilt() && !IsReputationDisabled(p->flow))
    {
        snort_reputation(config, p);
        DisableReputation(p->flow);
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
    (uint16_t)PktType::ANY_IP,
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

