//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "parser/parse_conf.h"
#include "parser/vars.h"
#include "ports/port_var_table.h"

#include "modules.h"
#include "shell.h"
#include "snort_config.h"

using namespace snort;

//-------------------------------------------------------------------------
// traffic policy
//-------------------------------------------------------------------------

NetworkPolicy::NetworkPolicy(PolicyId id, PolicyId default_inspection_id)
    : policy_id(id), default_inspection_policy_id(default_inspection_id)
{ init(nullptr, nullptr); }

NetworkPolicy::NetworkPolicy(NetworkPolicy* other_network_policy, const char* exclude_name)
{ init(other_network_policy, exclude_name); }

NetworkPolicy::~NetworkPolicy()
{
    FilePolicyBase::delete_file_policy(file_policy);
    InspectorManager::delete_policy(this, cloned);
}

void NetworkPolicy::init(NetworkPolicy* other_network_policy, const char* exclude_name)
{
    file_policy = new FilePolicy;
    if (other_network_policy)
    {
        dbus.clone(other_network_policy->dbus, exclude_name);
        policy_id = other_network_policy->policy_id;
        default_inspection_policy_id = other_network_policy->default_inspection_policy_id;
        user_policy_id = other_network_policy->user_policy_id;

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
{ file_policy->insert_file_rule(file_rule); }

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
}

void InspectionPolicy::configure()
{
    dbus.subscribe(PACKET_EVENT, new AltPktHandler);
}

//-------------------------------------------------------------------------
// detection policy
//-------------------------------------------------------------------------

IpsPolicy::IpsPolicy(PolicyId id) : action(Actions::get_max_types(), nullptr)
{
    policy_id = id;
    user_policy_id = 0;
    policy_mode = POLICY_MODE__MAX;

    var_table = nullptr;

    var_id = 1;
    ip_vartable = sfvt_alloc_table();
    portVarTable = PortVarTableCreate();
    nonamePortVarTable = PortTableNew();

    enable_builtin_rules = false;
    obfuscate_pii = false;
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
    if ( other_map )
        clone(other_map, exclude_name);
    else
    {
        file_id = InspectorManager::create_single_instance_inspector_policy();
        flow_tracking = InspectorManager::create_single_instance_inspector_policy();
        global_inspector_policy = InspectorManager::create_global_inspector_policy();
        add_shell(new Shell(nullptr, true), true);
        empty_ips_policy = new IpsPolicy(ips_policy.size());
        ips_policy.push_back(empty_ips_policy);
    }

    set_network_policy(network_policy[0]);
    set_inspection_policy(inspection_policy[0]);
    set_ips_policy(ips_policy[0]);
}

PolicyMap::~PolicyMap()
{
    if ( cloned )
    {
        if ( !inspection_policy.empty() )
        {
            InspectionPolicy* default_policy = inspection_policy[0];
            default_policy->cloned = true;
            delete default_policy;
        }
        if ( !network_policy.empty() )
        {
            NetworkPolicy* default_policy = network_policy[0];
            default_policy->cloned = true;
            delete default_policy;
        }
    }
    else
    {
        for ( auto p : shells )
            delete p;

        for ( auto p : inspection_policy )
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
    inspection_policy.clear();
    ips_policy.clear();
    network_policy.clear();
    shell_map.clear();
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

    for ( unsigned i = 0; i < (other_map->network_policy.size()); i++)
    {
        if ( i == 0 )
            network_policy.emplace_back(new NetworkPolicy(other_map->network_policy[i],
                exclude_name));
        else
            network_policy.emplace_back(other_map->network_policy[i]);
    }

    for ( unsigned i = 0; i < (other_map->inspection_policy.size()); i++)
    {
        if ( i == 0 )
            inspection_policy.emplace_back(new InspectionPolicy(other_map->inspection_policy[i]));
        else
            inspection_policy.emplace_back(other_map->inspection_policy[i]);
    }

    shell_map = other_map->shell_map;
    // Fix references to network_policy[0] and inspection_policy[0]
    for ( auto p : other_map->shell_map )
    {
        if ( p.second->network == other_map->network_policy[0] )
            shell_map[p.first]->network = network_policy[0];
        if ( p.second->inspection == other_map->inspection_policy[0] )
            shell_map[p.first] = std::make_shared<PolicyTuple>(inspection_policy[0], p.second->ips,
                p.second->network);
    }

    user_network = other_map->user_network;
    // Fix references to network_policy[0]
    for ( auto p : other_map->user_network )
    {
        if ( p.second == other_map->network_policy[0] )
            user_network[p.first] = network_policy[0];
    }

    user_inspection = other_map->user_inspection;
    // Fix references to inspection_policy[0]
    for ( auto p : other_map->user_inspection )
    {
        if ( p.second == other_map->inspection_policy[0] )
            user_inspection[p.first] = inspection_policy[0];
    }

    user_ips = other_map->user_ips;
}

InspectionPolicy* PolicyMap::add_inspection_shell(Shell* sh)
{
    unsigned idx = inspection_policy.size();
    InspectionPolicy* p = new InspectionPolicy(idx);

    shells.push_back(sh);
    inspection_policy.push_back(p);
    shell_map[sh] = std::make_shared<PolicyTuple>(p, nullptr, nullptr);

    return p;
}

IpsPolicy* PolicyMap::add_ips_shell(Shell* sh)
{
    unsigned idx = ips_policy.size();
    IpsPolicy* p = new IpsPolicy(idx);

    shells.push_back(sh);
    ips_policy.push_back(p);
    shell_map[sh] = std::make_shared<PolicyTuple>(nullptr, p, nullptr);

    return p;
}

std::shared_ptr<PolicyTuple> PolicyMap::add_shell(Shell* sh, bool include_network)
{
    shells.push_back(sh);
    inspection_policy.push_back(new InspectionPolicy(inspection_policy.size()));
    InspectionPolicy* ip = inspection_policy.back();
    NetworkPolicy* new_network_policy = nullptr;
    if (include_network)
    {
        new_network_policy = new NetworkPolicy(network_policy.size(), ip->policy_id);
        network_policy.push_back(new_network_policy);
    }
    ips_policy.push_back(new IpsPolicy(ips_policy.size()));
    return shell_map[sh] = std::make_shared<PolicyTuple>(ip,
        ips_policy.back(), new_network_policy);
}

std::shared_ptr<PolicyTuple> PolicyMap::get_policies(Shell* sh)
{
    const auto& pt = shell_map.find(sh);

    return pt == shell_map.end() ? nullptr : pt->second;
}

//-------------------------------------------------------------------------
// policy nav
//-------------------------------------------------------------------------

static THREAD_LOCAL NetworkPolicy* s_traffic_policy = nullptr;
static THREAD_LOCAL InspectionPolicy* s_inspection_policy = nullptr;
static THREAD_LOCAL IpsPolicy* s_detection_policy = nullptr;

namespace snort
{
NetworkPolicy* get_network_policy()
{ return s_traffic_policy; }

InspectionPolicy* get_inspection_policy()
{ return s_inspection_policy; }

IpsPolicy* get_ips_policy()
{ return s_detection_policy; }

void set_network_policy(NetworkPolicy* p)
{ s_traffic_policy = p; }

void set_inspection_policy(InspectionPolicy* p)
{ s_inspection_policy = p; }

void set_ips_policy(IpsPolicy* p)
{ s_detection_policy = p; }

InspectionPolicy* get_user_inspection_policy(const SnortConfig* sc, unsigned policy_id)
{
    return sc->policy_map->get_user_inspection(policy_id);
}

NetworkPolicy* get_default_network_policy(const SnortConfig* sc)
{ return sc->policy_map->get_network_policy(0); }

InspectionPolicy* get_default_inspection_policy(const SnortConfig* sc)
{
    return
        sc->policy_map->get_inspection_policy(get_network_policy()->default_inspection_policy_id);
}

IpsPolicy* get_ips_policy(const SnortConfig* sc, unsigned i)
{
    return sc && i < sc->policy_map->ips_policy_count() ?
        sc->policy_map->get_ips_policy(i) : nullptr;
}

IpsPolicy* get_user_ips_policy(const SnortConfig* sc, unsigned policy_id)
{
    return sc->policy_map->get_user_ips(policy_id);
}

IpsPolicy* get_empty_ips_policy(const SnortConfig* sc)
{
    return sc->policy_map->get_empty_ips();
}
} // namespace snort

void set_network_policy(const SnortConfig* sc, unsigned i)
{
    PolicyMap* pm = sc->policy_map;

    if ( i < pm->network_policy_count() )
        set_network_policy(pm->get_network_policy(i));
}

void set_inspection_policy(const SnortConfig* sc, unsigned i)
{
    PolicyMap* pm = sc->policy_map;

    if ( i < pm->inspection_policy_count() )
        set_inspection_policy(pm->get_inspection_policy(i));
}

void set_ips_policy(const SnortConfig* sc, unsigned i)
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
    set_network_policy(sc->policy_map->get_network_policy(0));
    set_inspection_policy(sc->policy_map->get_inspection_policy(0));
    set_ips_policy(sc->policy_map->get_ips_policy(0));
}

void select_default_policy(const _daq_pkt_hdr* pkthdr, const SnortConfig* sc)
{
    PolicySelector* ps = sc->policy_map->get_policy_selector();
    if (!ps || !ps->select_default_policies(pkthdr, sc))
    {
        set_network_policy(sc->policy_map->get_network_policy(0));
        set_inspection_policy(sc->policy_map->get_inspection_policy(0));
        set_ips_policy(sc->policy_map->get_ips_policy(0));
    }
}

bool only_inspection_policy()
{ return get_inspection_policy() && !get_ips_policy() && !get_network_policy(); }

bool only_ips_policy()
{ return get_ips_policy() && !get_inspection_policy() && !get_network_policy(); }

