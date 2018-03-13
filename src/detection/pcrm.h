//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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

// pcrm.h is a heavily refactored version of work by:
//
// Marc Norton <mnorton@sourcefire.com>
// Dan Roelker <droelker@sourcefire.com>

#ifndef PCRM_H
#define PCRM_H

// Packet Classification-Rule Manager
// rule groups by source and dest ports as well as any
// (generic refers to any)

#include "ports/port_group.h"
#include "protocols/packet.h"

#define ANYPORT (-1)

struct PORT_RULE_MAP
{
    int prmNumDstRules;
    int prmNumSrcRules;
    int prmNumGenericRules;

    int prmNumDstGroups;
    int prmNumSrcGroups;

    PortGroup* prmSrcPort[snort::MAX_PORTS];
    PortGroup* prmDstPort[snort::MAX_PORTS];
    PortGroup* prmGeneric;
};

PORT_RULE_MAP* prmNewMap();

int prmFindRuleGroupTcp(PORT_RULE_MAP*, int, int, PortGroup**, PortGroup**, PortGroup**);
int prmFindRuleGroupUdp(PORT_RULE_MAP*, int, int, PortGroup**, PortGroup**, PortGroup**);
int prmFindRuleGroupIp(PORT_RULE_MAP*, int, PortGroup**, PortGroup**);
int prmFindRuleGroupIcmp(PORT_RULE_MAP*, int, PortGroup**, PortGroup**);

#endif

