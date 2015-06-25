//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

// service_map.h based fp_create.h by:
/*
** Dan Roelker <droelker@sourcefire.com>
** Marc Norton <mnorton@sourcefire.com>
**
** NOTES
** 5.7.02 - Initial Sourcecode.  Norton/Roelker
** 6/13/05 - marc norton
**   Added plugin support for fast pattern match data
*/
#ifndef SERVICE_MAP_H
#define SERVICE_MAP_H

#include "detection/pcrm.h"
#include "target_based/snort_protocols.h"

struct SFGHASH;

//  Service Rule Map Master Table
struct srmm_table_t
{
    SFGHASH* ip_to_srv;
    SFGHASH* ip_to_cli;

    SFGHASH* icmp_to_srv;
    SFGHASH* icmp_to_cli;

    SFGHASH* tcp_to_srv;
    SFGHASH* tcp_to_cli;

    SFGHASH* udp_to_srv;
    SFGHASH* udp_to_cli;

    SFGHASH* svc_to_srv;
    SFGHASH* svc_to_cli;
};

srmm_table_t* ServiceMapNew();
void ServiceMapFree(srmm_table_t*);

srmm_table_t* ServicePortGroupMapNew();
void ServicePortGroupMapFree(srmm_table_t*);

void ServiceTableFree(SFGHASH*);
void fpPrintServicePortGroupSummary(srmm_table_t*);
int fpCreateServiceMaps(struct SnortConfig*);

//  Service/Protocol Oridinal To PortGroup table
struct sopg_table_t
{
    PortGroup* ip_to_srv[MAX_PROTOCOL_ORDINAL];
    PortGroup* ip_to_cli[MAX_PROTOCOL_ORDINAL];

    PortGroup* icmp_to_srv[MAX_PROTOCOL_ORDINAL];
    PortGroup* icmp_to_cli[MAX_PROTOCOL_ORDINAL];

    PortGroup* tcp_to_srv[MAX_PROTOCOL_ORDINAL];
    PortGroup* tcp_to_cli[MAX_PROTOCOL_ORDINAL];

    PortGroup* udp_to_srv[MAX_PROTOCOL_ORDINAL];
    PortGroup* udp_to_cli[MAX_PROTOCOL_ORDINAL];

    PortGroup* svc_to_srv[MAX_PROTOCOL_ORDINAL];
    PortGroup* svc_to_cli[MAX_PROTOCOL_ORDINAL];
};

sopg_table_t* ServicePortGroupTableNew();

PortGroup* fpGetServicePortGroupByOrdinal(
    sopg_table_t* sopg, int proto, int dir, int16_t proto_ordinal);

#endif

