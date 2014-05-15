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
    checksum_drop = CHECKSUM_FLAG__DEF;
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
    normal_mask = 0;
    scanned_proto_mask = 0;

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
    inspection_policy.push_back(new InspectionPolicy);
    ips_policy.push_back(new IpsPolicy);
    network_policy.push_back(new NetworkPolicy);

    set_inspection_policy(inspection_policy[0]);
    set_ips_policy(ips_policy[0]);
    set_network_policy(network_policy[0]);
}

PolicyMap::~PolicyMap()
{
    for ( auto p : inspection_policy )
        delete p;

    for ( auto p : ips_policy )
        delete p;

    for ( auto p : network_policy )
        delete p;

    inspection_policy.clear();
    ips_policy.clear();
    network_policy.clear();
}

