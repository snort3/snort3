//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "parser/vars.h"
#include "ports/port_var_table.h"

#include "modules.h"
#include "shell.h"
#include "snort_config.h"

//-------------------------------------------------------------------------
// traffic policy
//-------------------------------------------------------------------------

NetworkPolicy::NetworkPolicy(PolicyId id)
{
    policy_id = id;
    user_policy_id = 0;

    // minimum possible (allows all but errors to pass by default)
    min_ttl = 1;
    new_ttl = 5;

    checksum_eval = CHECKSUM_FLAG__ALL | CHECKSUM_FLAG__DEF;
    checksum_drop = CHECKSUM_FLAG__DEF;
}


//-------------------------------------------------------------------------
// inspection policy
//-------------------------------------------------------------------------

class AltPktHandler : public DataHandler
{
public:
    AltPktHandler() = default;

    void handle(DataEvent& e, Flow*) override
    { DetectionEngine::detect((Packet*)e.get_packet()); }  // FIXIT-L not const!
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

IpsPolicy::IpsPolicy(PolicyId id)
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

PolicyMap::PolicyMap(PolicyMap* other_map)
{
    if ( other_map )
        clone(other_map);
    else
        add_shell(new Shell);

    set_inspection_policy(inspection_policy[0]);
    set_ips_policy(ips_policy[0]);
    set_network_policy(network_policy[0]);
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
    }

    shells.clear();
    inspection_policy.clear();
    ips_policy.clear();
    network_policy.clear();
    shell_map.clear();
}

void PolicyMap::clone(PolicyMap *other_map)
{
    shells = other_map->shells;
    ips_policy = other_map->ips_policy;
    network_policy = other_map->network_policy;

    for ( unsigned i = 0; i < (other_map->inspection_policy.size()); i++)
    {
        if ( i == 0 )
        {
            inspection_policy.push_back(new InspectionPolicy(other_map->inspection_policy[i]));
        }
        else
            inspection_policy.push_back(other_map->inspection_policy[i]);
    }
}

unsigned PolicyMap::add_inspection_shell(Shell* sh)
{
    unsigned idx = inspection_policy.size();
    shells.push_back(sh);
    inspection_policy.push_back(new InspectionPolicy(idx));

    shell_map[sh] = std::make_shared<PolicyTuple>(inspection_policy.back(), nullptr, nullptr);
    return idx;
}

unsigned PolicyMap::add_ips_shell(Shell* sh)
{
    unsigned idx = ips_policy.size();
    shells.push_back(sh);
    ips_policy.push_back(new IpsPolicy(idx));
    shell_map[sh] = std::make_shared<PolicyTuple>(nullptr, ips_policy.back(), nullptr);
    return idx;
}

unsigned PolicyMap::add_network_shell(Shell* sh)
{
    unsigned idx = network_policy.size();
    shells.push_back(sh);
    network_policy.push_back(new NetworkPolicy(idx));
    shell_map[sh] = std::make_shared<PolicyTuple>(nullptr, nullptr, network_policy.back());
    return idx;
}

std::shared_ptr<PolicyTuple> PolicyMap::add_shell(Shell* sh)
{
    shells.push_back(sh);
    inspection_policy.push_back(new InspectionPolicy(inspection_policy.size()));
    ips_policy.push_back(new IpsPolicy(ips_policy.size()));
    network_policy.push_back(new NetworkPolicy(network_policy.size()));

    return shell_map[sh] = std::make_shared<PolicyTuple>(inspection_policy.back(),
        ips_policy.back(), network_policy.back());
}

//-------------------------------------------------------------------------
// policy nav
//-------------------------------------------------------------------------

static THREAD_LOCAL NetworkPolicy* s_traffic_policy = nullptr;
static THREAD_LOCAL InspectionPolicy* s_inspection_policy = nullptr;
static THREAD_LOCAL IpsPolicy* s_detection_policy = nullptr;

NetworkPolicy* get_network_policy()
{ return s_traffic_policy; }

InspectionPolicy* get_inspection_policy()
{ return s_inspection_policy; }

IpsPolicy* get_ips_policy()
{ return s_detection_policy; }

void set_network_policy(NetworkPolicy* p)
{ s_traffic_policy = p; }

void set_network_policy(SnortConfig* sc, unsigned i)
{
    PolicyMap* pm = sc->policy_map;

    if ( i < pm->network_policy.size() )
        set_network_policy(pm->network_policy[i]);
}

void set_inspection_policy(InspectionPolicy* p)
{ s_inspection_policy = p; }

void set_inspection_policy(SnortConfig* sc, unsigned i)
{
    PolicyMap* pm = sc->policy_map;

    if ( i < pm->inspection_policy.size() )
        set_inspection_policy(pm->inspection_policy[i]);
}

void set_ips_policy(IpsPolicy* p)
{ s_detection_policy = p; }

void set_user_ips_policy(unsigned policy_id)
{
    IpsPolicy *p = SnortConfig::get_conf()->policy_map->get_user_ips(policy_id);
    if(!p)
    {
        ips_module_stats.invalid_policy_ids++;
        return;
    }

    s_detection_policy = p;
}

void set_ips_policy(SnortConfig* sc, unsigned i)
{
    PolicyMap* pm = sc->policy_map;

    if ( i < pm->ips_policy.size() )
        set_ips_policy(pm->ips_policy[i]);
}

void set_policies(SnortConfig* sc, Shell* sh)
{
    auto policies = sc->policy_map->shell_map[sh];

    if ( policies->inspection )
        set_inspection_policy(policies->inspection);

    if ( policies->ips )
        set_ips_policy(policies->ips);

    if ( policies->network )
        set_network_policy(policies->network);
}

void set_default_policy(SnortConfig* sc)
{
    set_network_policy(sc->policy_map->network_policy[0]);
    set_inspection_policy(sc->policy_map->inspection_policy[0]);
    set_ips_policy(sc->policy_map->ips_policy[0]);
}

void set_default_policy()
{ set_default_policy(SnortConfig::get_conf()); }

bool only_inspection_policy()
{ return get_inspection_policy() && !get_ips_policy() && !get_network_policy(); }

bool only_ips_policy()
{ return get_ips_policy() && !get_inspection_policy() && !get_network_policy(); }

bool only_network_policy()
{ return get_network_policy() && !get_ips_policy() && !get_inspection_policy(); }

