//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "policy.h"

#include "daq_common.h"

#include "actions/actions.h"
#include "detection/detection_engine.h"
#include "framework/file_policy.h"
#include "framework/policy_selector.h"
#include "js_norm/js_config.h"
#include "log/messages.h"
#include "main/thread_config.h"
#include "managers/inspector_manager.h"
#include "parser/parse_conf.h"
#include "parser/vars.h"
#include "ports/port_var_table.h"
#include "pub_sub/intrinsic_event_ids.h"

#include "modules.h"
#include "shell.h"
#include "snort_config.h"

using namespace snort;

//-------------------------------------------------------------------------
// traffic policy
//-------------------------------------------------------------------------

NetworkPolicy::NetworkPolicy(PolicyId id, PolicyId default_ips_id)
    : policy_id(id), default_ips_policy_id(default_ips_id)
{ init(nullptr, nullptr); }

NetworkPolicy::NetworkPolicy(NetworkPolicy* other_network_policy, const char* exclude_name)
{ init(other_network_policy, exclude_name); }

NetworkPolicy::~NetworkPolicy()
{
    FilePolicyBase::delete_file_policy(file_policy);
    if (cloned)
    {
        if ( !inspection_policy.empty() )
        {
            InspectionPolicy* default_policy = inspection_policy[0];
            default_policy->cloned = true;
            delete default_policy;
        }
    }
    else
    {
        for ( auto p : inspection_policy )
            delete p;
    }

    InspectorManager::delete_policy(this, cloned);

    inspection_policy.clear();
}

void NetworkPolicy::init(NetworkPolicy* other_network_policy, const char* exclude_name)
{
    file_policy = new FilePolicy;
    if (other_network_policy)
    {
        for ( unsigned i = 0; i < (other_network_policy->inspection_policy.size()); i++)
        {
            if ( i == 0 )
                inspection_policy.emplace_back(
                    new InspectionPolicy(other_network_policy->inspection_policy[i]));
            else
                inspection_policy.emplace_back(other_network_policy->inspection_policy[i]);
        }
        user_inspection = other_network_policy->user_inspection;
        // Fix references to inspection_policy[0]
        for ( auto p : other_network_policy->user_inspection )
        {
            if ( p.second == other_network_policy->inspection_policy[0] )
                user_inspection[p.first] = inspection_policy[0];
        }


        dbus.clone(other_network_policy->dbus, exclude_name);
        policy_id = other_network_policy->policy_id;
        user_policy_id = other_network_policy->user_policy_id;
        default_ips_policy_id = other_network_policy->default_ips_policy_id;

        min_ttl = other_network_policy->min_ttl;
        new_ttl = other_network_policy->new_ttl;

        checksum_eval = other_network_policy->checksum_eval;
        checksum_drop = other_network_policy->checksum_drop;
        normal_mask = other_network_policy->normal_mask;
    }
    InspectorManager::new_policy(this, other_network_policy);
}

FilePolicyBase* NetworkPolicy::get_base_file_policy() const
{ return file_policy; }
FilePolicy* NetworkPolicy::get_file_policy() const
{ return file_policy; }

void NetworkPolicy::add_file_policy_rule(FileRule& file_rule)
{ file_policy->add_file_id(file_rule); }

InspectionPolicy* NetworkPolicy::get_user_inspection_policy(unsigned user_id)
{
    auto it = user_inspection.find(user_id);
    return it == user_inspection.end() ? nullptr : it->second;
}

//-------------------------------------------------------------------------
// inspection policy
//-------------------------------------------------------------------------

class AltPktHandler : public DataHandler
{
public:
    AltPktHandler() : DataHandler("detection") { }

    void handle(DataEvent& e, Flow*) override
    { DetectionEngine::detect(const_cast<Packet*>(e.get_packet())); }
};

InspectionPolicy::InspectionPolicy(PolicyId id)
{
    policy_id = id;
    init(nullptr);
}

InspectionPolicy::InspectionPolicy(InspectionPolicy* other_inspection_policy)
{ init(other_inspection_policy); }

void InspectionPolicy::init(InspectionPolicy* other_inspection_policy)
{
    framework_policy = nullptr;
    cloned = false;
    if (other_inspection_policy)
    {
        policy_id = other_inspection_policy->policy_id;
        policy_mode = other_inspection_policy->policy_mode;
        user_policy_id = other_inspection_policy->user_policy_id;
#ifdef HAVE_UUID
        uuid_copy(uuid, other_inspection_policy->uuid);
#endif
    }
    InspectorManager::new_policy(this, other_inspection_policy);
}

InspectionPolicy::~InspectionPolicy()
{
    InspectorManager::delete_policy(this, cloned);
    delete jsn_config;
}

void InspectionPolicy::configure()
{
    dbus.subscribe(intrinsic_pub_key, IntrinsicEventIds::ALT_PACKET, new AltPktHandler);
}

//-------------------------------------------------------------------------
// detection policy
//-------------------------------------------------------------------------

IpsPolicy::IpsPolicy(PolicyId id) : action(Actions::get_max_types(), nullptr)
{
    policy_id = id;
    policy_mode = POLICY_MODE__MAX;

    var_table = nullptr;

    var_id = 1;
    ip_vartable = sfvt_alloc_table();
    portVarTable = PortVarTableCreate();
    nonamePortVarTable = PortTableNew();

    enable_builtin_rules = false;
    obfuscate_pii = true;
}

IpsPolicy::~IpsPolicy()
{
    if ( var_table )
        DeleteVars(var_table);

    if ( ip_vartable )
        sfvt_free_table(ip_vartable);

    if ( portVarTable )
        PortVarTableFree(portVarTable);

    if ( nonamePortVarTable )
        PortTableFree(nonamePortVarTable);
}

//-------------------------------------------------------------------------
// policy map
//-------------------------------------------------------------------------

PolicyMap::PolicyMap(PolicyMap* other_map, const char* exclude_name)
{
    unsigned max = ThreadConfig::get_instance_max();
    inspector_tinit_complete = new bool[max]{};
    if ( other_map )
        clone(other_map, exclude_name);
    else
    {
        file_id = InspectorManager::create_single_instance_inspector_policy();
        flow_tracking = InspectorManager::create_single_instance_inspector_policy();
        global_inspector_policy = InspectorManager::create_global_inspector_policy();
        add_shell(new Shell(nullptr, true), nullptr);
        empty_ips_policy = new IpsPolicy(ips_policy.size());
        ips_policy.push_back(empty_ips_policy);
    }

    set_network_policy(network_policy[0]);
    set_network_parse_policy(network_policy[0]);
    set_inspection_policy(network_policy[0]->get_inspection_policy(0));
    set_ips_policy(ips_policy[0]);
}

PolicyMap::~PolicyMap()
{
    if ( cloned )
    {
        for (auto np: network_policy)
        {
            np->cloned = true;
            delete np;
        }
    }
    else
    {
        for ( auto p : shells )
            delete p;

        for ( auto p : ips_policy )
            delete p;

        for ( auto p : network_policy )
            delete p;

        InspectorManager::destroy_single_instance_inspector(flow_tracking);
        InspectorManager::destroy_single_instance_inspector(file_id);
    }

    PolicySelector::free_policy_selector(selector);
    InspectorManager::destroy_global_inspector_policy(global_inspector_policy, cloned);

    shells.clear();
    ips_policy.clear();
    network_policy.clear();
    shell_map.clear();
    delete[] inspector_tinit_complete;
}

bool PolicyMap::setup_network_policies()
{
    for (auto* np : network_policy)
    {
        if (!set_user_network(np))
            return false;
    }
    return true;
}

void PolicyMap::clone(PolicyMap *other_map, const char* exclude_name)
{
    global_inspector_policy =
        InspectorManager::create_global_inspector_policy(other_map->global_inspector_policy);
    file_id = other_map->file_id;
    flow_tracking = other_map->flow_tracking;
    shells = other_map->shells;
    ips_policy = other_map->ips_policy;
    empty_ips_policy = other_map->empty_ips_policy;

    for ( unsigned i = 0; i < other_map->network_policy.size(); i++)
        network_policy.emplace_back(new NetworkPolicy(other_map->network_policy[i],
            i ? nullptr : exclude_name));

    shell_map = other_map->shell_map;
    // Fix references to network_policy[0] and inspection_policy[0]
    for ( auto p : other_map->shell_map )
    {
        for ( unsigned idx = 0; idx < other_map->network_policy.size(); ++idx)
        {
            if ( p.second->network == other_map->network_policy[idx] )
            {
                shell_map[p.first]->network = network_policy[idx];
                shell_map[p.first]->network_parse = network_policy[idx];
            }
            if ( p.second->inspection == other_map->network_policy[idx]->inspection_policy[0] )
                shell_map[p.first] =
                    std::make_shared<PolicyTuple>(
                        other_map->network_policy[idx]->inspection_policy[0], p.second->ips,
                        p.second->network, p.second->network);
        }
    }

    //user_network = other_map->user_network;
    user_ips = other_map->user_ips;
}

InspectionPolicy* PolicyMap::add_inspection_shell(Shell* sh)
{
    NetworkPolicy* np = get_network_parse_policy();
    assert(np);
    unsigned idx = np->inspection_policy_count();
    InspectionPolicy* ip = new InspectionPolicy(idx);

    shells.push_back(sh);
    np->inspection_policy.push_back(ip);
    shell_map[sh] = std::make_shared<PolicyTuple>(ip, nullptr, nullptr, np);

    return ip;
}

IpsPolicy* PolicyMap::add_ips_shell(Shell* sh)
{
    unsigned idx = ips_policy.size();
    IpsPolicy* p = new IpsPolicy(idx);

    shells.push_back(sh);
    ips_policy.push_back(p);
    shell_map[sh] = std::make_shared<PolicyTuple>(nullptr, p, nullptr, get_network_parse_policy());

    return p;
}

std::shared_ptr<PolicyTuple> PolicyMap::add_shell(Shell* sh, NetworkPolicy* np_in)
{
    shells.push_back(sh);
    IpsPolicy* ips = new IpsPolicy(ips_policy.size());
    ips_policy.push_back(ips);
    NetworkPolicy* np;
    if (!np_in)
    {
        np_in = np = new NetworkPolicy(network_policy.size(), ips->policy_id);
        network_policy.push_back(np);
    }
    else
    {
        np = np_in;
        np_in = nullptr;
    }
    InspectionPolicy* ip = new InspectionPolicy(np->inspection_policy_count());
    np->inspection_policy.push_back(ip);
    return shell_map[sh] =
        std::make_shared<PolicyTuple>(ip, ips, np_in, np);
}

std::shared_ptr<PolicyTuple> PolicyMap::get_policies(Shell* sh)
{
    const auto& pt = shell_map.find(sh);

    return pt == shell_map.end() ? nullptr : pt->second;
}

NetworkPolicy* PolicyMap::get_user_network(uint64_t user_id) const
{
    auto it = user_network.find(user_id);
    NetworkPolicy* np = (it == user_network.end()) ? nullptr : it->second;
    return np;
}

bool PolicyMap::set_user_network(NetworkPolicy* p)
{
    NetworkPolicy* current_np = get_user_network(p->user_policy_id);
    if (current_np && p != current_np)
        return false;
    user_network[p->user_policy_id] = p;
    return true;
}


//-------------------------------------------------------------------------
// policy nav
//-------------------------------------------------------------------------

static THREAD_LOCAL NetworkPolicy* s_network_policy = nullptr;
static THREAD_LOCAL NetworkPolicy* s_network_parse_policy = nullptr;
static THREAD_LOCAL InspectionPolicy* s_inspection_policy = nullptr;
static THREAD_LOCAL IpsPolicy* s_detection_policy = nullptr;

namespace snort
{
NetworkPolicy* get_network_policy()
{ return s_network_policy; }

NetworkPolicy* get_network_parse_policy()
{ return s_network_parse_policy; }

InspectionPolicy* get_inspection_policy()
{ return s_inspection_policy; }

IpsPolicy* get_ips_policy()
{ return s_detection_policy; }

void set_network_parse_policy(NetworkPolicy* p)
{ s_network_parse_policy = p; }

void set_network_policy(NetworkPolicy* p)
{ s_network_policy = p; }

void set_inspection_policy(InspectionPolicy* p)
{ s_inspection_policy = p; }

void set_ips_policy(IpsPolicy* p)
{ s_detection_policy = p; }

InspectionPolicy* get_user_inspection_policy(unsigned policy_id)
{
    NetworkPolicy* np = get_network_policy();
    assert(np);
    return np->get_user_inspection_policy(policy_id);
}

NetworkPolicy* get_default_network_policy(const SnortConfig* sc)
{ return sc->policy_map->get_network_policy(0); }

IpsPolicy* get_ips_policy(const SnortConfig* sc, unsigned i)
{
    return sc && i < sc->policy_map->ips_policy_count() ?
        sc->policy_map->get_ips_policy(i) : nullptr;
}

IpsPolicy* get_default_ips_policy(const snort::SnortConfig* sc)
{
    NetworkPolicy* np = get_network_policy();
    assert(np);
    return np->get_default_ips_policy(sc);
}

IpsPolicy* get_user_ips_policy(const SnortConfig* sc, unsigned policy_id)
{ return sc->policy_map->get_user_ips(policy_id); }

IpsPolicy* get_empty_ips_policy(const SnortConfig* sc)
{ return sc->policy_map->get_empty_ips(); }
} // namespace snort

void set_network_policy(unsigned i)
{
    PolicyMap* pm = SnortConfig::get_conf()->policy_map;
    NetworkPolicy* np = pm->get_network_policy(i);
    if ( np )
        set_network_policy(np);
}

void set_inspection_policy(unsigned i)
{
    NetworkPolicy* np = get_network_policy();
    if (np)
    {
        InspectionPolicy* ip = np->get_inspection_policy(i);
        if (ip)
            set_inspection_policy(ip);
    }
}

void set_ips_policy(const snort::SnortConfig* sc, unsigned i)
{
    PolicyMap* pm = sc->policy_map;

    if ( i < pm->ips_policy_count() )
        set_ips_policy(pm->get_ips_policy(i));
}

void set_policies(const SnortConfig* sc, Shell* sh)
{
    auto policies = sc->policy_map->get_policies(sh);

    if ( policies->inspection )
        set_inspection_policy(policies->inspection);

    if ( policies->ips )
        set_ips_policy(policies->ips);

    if ( policies->network )
        set_network_policy(policies->network);
}

void set_default_policy(const SnortConfig* sc)
{
    NetworkPolicy* np = get_default_network_policy(sc);
    set_network_policy(np);
    set_inspection_policy(np->get_inspection_policy(0));
    set_ips_policy(get_ips_policy(sc, 0));
}

void select_default_policy(const _daq_pkt_hdr& pkthdr, const SnortConfig* sc)
{
    PolicySelector* ps = sc->policy_map->get_policy_selector();
    if (!ps || !ps->select_default_policies(pkthdr, sc))
        set_default_policy(sc);
}

void select_default_policy(const _daq_flow_stats& stats, const snort::SnortConfig* sc)
{
    PolicySelector* ps = sc->policy_map->get_policy_selector();
    if (!ps || !ps->select_default_policies(stats, sc))
        set_default_policy(sc);
}

bool only_inspection_policy()
{ return get_inspection_policy() && !get_ips_policy() && !get_network_policy(); }

bool only_ips_policy()
{ return get_ips_policy() && !get_inspection_policy() && !get_network_policy(); }

