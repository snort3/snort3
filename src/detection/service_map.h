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

// service_map.h based fp_create.h by:
//
// Dan Roelker <droelker@sourcefire.com>
// Marc Norton <mnorton@sourcefire.com>

#ifndef SERVICE_MAP_H
#define SERVICE_MAP_H

//  for managing rule groups by service
//  direction to client and to server are separate

#include <vector>

#include "target_based/snort_protocols.h"

namespace snort
{
struct SnortConfig;
struct GHash;
}
struct PortGroup;

//  Service Rule Map Master Table
struct srmm_table_t
{
    snort::GHash* to_srv[SNORT_PROTO_MAX];
    snort::GHash* to_cli[SNORT_PROTO_MAX];
};

srmm_table_t* ServiceMapNew();
void ServiceMapFree(srmm_table_t*);

srmm_table_t* ServicePortGroupMapNew();
void ServicePortGroupMapFree(srmm_table_t*);

void fpPrintServicePortGroupSummary(snort::SnortConfig*);
int fpCreateServiceMaps(snort::SnortConfig*);

//  Service/Protocol Ordinal To PortGroup table
typedef std::vector<PortGroup*> PortGroupVector;

struct sopg_table_t
{
    sopg_table_t(unsigned size);
    bool set_user_mode();
    PortGroup* get_port_group(SnortProtocolId proto_id, bool c2s, SnortProtocolId snort_protocol_id);

    PortGroupVector to_srv[SNORT_PROTO_MAX];
    PortGroupVector to_cli[SNORT_PROTO_MAX];

    bool user_mode;
};


#endif

