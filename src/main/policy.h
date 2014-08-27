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

#ifndef SNORT_POLICY_H
#define SNORT_POLICY_H

#include <string>
#include <vector>

#include "snort_types.h"
#include "sfip/sf_ipvar.h"
#include "utils/sfportobject.h"
#include "sfip/ipv6_port.h"

typedef unsigned int PolicyId;

// FIXIT-L split into separate headers

//-------------------------------------------------------------------------
// traffic stuff
//-------------------------------------------------------------------------

enum ChecksumFlag
{
    CHECKSUM_FLAG__IP   = 0x00000001,
    CHECKSUM_FLAG__TCP  = 0x00000002,
    CHECKSUM_FLAG__UDP  = 0x00000004,
    CHECKSUM_FLAG__ICMP = 0x00000008,
    CHECKSUM_FLAG__ALL  = 0x0000000f,
    CHECKSUM_FLAG__DEF  = 0x80000000
};

enum DecodeEventFlag
{
    DECODE_EVENT_FLAG__DEFAULT = 0x00000001
};

// Snort ac-split creates the nap
// Snort++ breaks that into network and inspection
struct NetworkPolicy
{
public:
    NetworkPolicy(PolicyId = 0);
    ~NetworkPolicy();

public:
    PolicyId policy_id;
    uint32_t user_policy_id;

    uint8_t min_ttl;
    uint8_t new_ttl;

    uint32_t checksum_eval;
    uint32_t checksum_drop;

    bool decoder_drop;
};

//-------------------------------------------------------------------------
// inspection stuff
//-------------------------------------------------------------------------

struct InspectionPolicy
{
public:
    InspectionPolicy();
    ~InspectionPolicy();

public:
    struct FrameworkPolicy* framework_policy;
};

//-------------------------------------------------------------------------
// detection stuff
//-------------------------------------------------------------------------

typedef struct _VarEntry
{
    char *name;
    char *value;

    unsigned char flags;
    uint32_t id;

    sfip_var_t *addrset;
    struct _VarEntry *prev;
    struct _VarEntry *next;

} VarEntry;

enum PolicyMode
{
    POLICY_MODE__PASSIVE,
    POLICY_MODE__INLINE,
    POLICY_MODE__INLINE_TEST
};

// this is the ips policy post ac-split
struct IpsPolicy
{
public:
    IpsPolicy(PolicyId = 0);
    ~IpsPolicy();

public:
    PolicyId policy_id;
    uint32_t user_policy_id;

    PolicyMode policy_mode;
    bool enable_builtin_rules;

    std::string include;
    std::string rules;

    uint32_t var_id;

    VarEntry *var_table;
    vartable_t *ip_vartable;

    /* The portobjects in these are attached to rtns and used during runtime */
    PortVarTable *portVarTable;     /* named entries, uses a hash table */
    PortTable *nonamePortVarTable;  /* un-named entries */
};

//-------------------------------------------------------------------------
// binding stuff - FIXIT-H tbd
//-------------------------------------------------------------------------

class PolicyMap
{
public:
    PolicyMap();
    ~PolicyMap();

    InspectionPolicy* get_inspection_policy()
    { return inspection_policy[0]; };

    IpsPolicy* get_ips_policy()
    { return ips_policy[0]; };
    
    NetworkPolicy* get_network_policy()
    { return network_policy[0]; };

public:
    std::vector<InspectionPolicy*> inspection_policy;
    std::vector<IpsPolicy*> ips_policy;
    std::vector<NetworkPolicy*> network_policy;
};

#endif

