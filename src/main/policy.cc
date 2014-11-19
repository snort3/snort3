/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "policy.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "managers/inspector_manager.h"
#include "parser/vars.h"
#include "main/shell.h"
#include "snort.h"

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
    checksum_drop = 0;
}

NetworkPolicy::~NetworkPolicy()
{
}

//-------------------------------------------------------------------------
// inspection policy
//-------------------------------------------------------------------------

InspectionPolicy::InspectionPolicy()
{
    framework_policy = nullptr;

    InspectorManager::new_policy(this);
}

InspectionPolicy::~InspectionPolicy()
{
    InspectorManager::delete_policy(this);
}

//-------------------------------------------------------------------------
// detection policy
//-------------------------------------------------------------------------

IpsPolicy::IpsPolicy(PolicyId id)
{
    policy_id = id;
    user_policy_id = 0;
    policy_mode = POLICY_MODE__PASSIVE;

    var_table = nullptr;
    var_id = 0;
    ip_vartable = nullptr;

    portVarTable = nullptr;
    nonamePortVarTable = nullptr;

    enable_builtin_rules = false;

    InitVarTables(this);
}

IpsPolicy::~IpsPolicy()
{
    VarTablesFree(this);
}

//-------------------------------------------------------------------------
// policy map
//-------------------------------------------------------------------------

PolicyMap::PolicyMap()
{
    add_shell(new Shell);

    set_inspection_policy(inspection_policy[0]);
    set_ips_policy(ips_policy[0]);
    set_network_policy(network_policy[0]);
}

PolicyMap::~PolicyMap()
{
    for ( auto p : shells )
        delete p;

    for ( auto p : inspection_policy )
        delete p;

    for ( auto p : ips_policy )
        delete p;

    for ( auto p : network_policy )
        delete p;

    shells.clear();
    inspection_policy.clear();
    ips_policy.clear();
    network_policy.clear();
}

unsigned PolicyMap::add_shell(Shell* sh)
{ 
    unsigned idx = shells.size();
    shells.push_back(sh);
    inspection_policy.push_back(new InspectionPolicy);  // FIXIT-H need id?
    ips_policy.push_back(new IpsPolicy(idx));
    network_policy.push_back(new NetworkPolicy(idx));
    return idx;
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

void set_inspection_policy(InspectionPolicy* p)
{ s_inspection_policy = p; }

void set_ips_policy(IpsPolicy* p)
{ s_detection_policy = p; }

void set_policies(SnortConfig* sc, unsigned i)
{
    PolicyMap* pm = sc->policy_map;

    if ( i < pm->shells.size() )
    {
        set_network_policy(pm->network_policy[i]);
        set_inspection_policy(pm->inspection_policy[i]);
        set_ips_policy(pm->ips_policy[i]);
    }
}

void set_default_policy()
{
    set_network_policy(snort_conf->policy_map->network_policy[0]);
    set_ips_policy(snort_conf->policy_map->ips_policy[0]);
    set_inspection_policy(snort_conf->policy_map->inspection_policy[0]);
}

