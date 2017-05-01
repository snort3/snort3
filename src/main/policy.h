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

#ifndef SNORT_POLICY_H
#define SNORT_POLICY_H

// the following policy types are defined:
//
// -- network - for packet handling
// -- inspection - for flow handling
// -- ips - for rule handling

#include "framework/data_bus.h"

struct PortTable;
struct vartable_t;
struct sfip_var_t;

typedef unsigned int PolicyId;
typedef struct SFGHASH PortVarTable;

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

// Snort ac-split creates the nap (network analysis policy)
// Snort++ breaks the nap into network and inspection
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
    uint32_t normal_mask;

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

    void configure();

public:
    struct FrameworkPolicy* framework_policy;
    DataBus dbus;
};

//-------------------------------------------------------------------------
// detection stuff
//-------------------------------------------------------------------------

enum PolicyMode
{
    POLICY_MODE__PASSIVE,
    POLICY_MODE__INLINE,
    POLICY_MODE__INLINE_TEST,
    POLICY_MODE__MAX
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

    struct VarEntry* var_table;
    vartable_t* ip_vartable;

    /* The portobjects in these are attached to rtns and used during runtime */
    PortVarTable* portVarTable;     /* named entries, uses a hash table */
    PortTable* nonamePortVarTable;  /* un-named entries */
};

//-------------------------------------------------------------------------
// binding stuff
//-------------------------------------------------------------------------

class Shell;

class PolicyMap
{
public:
    PolicyMap();
    ~PolicyMap();

    unsigned add_shell(Shell*);

    Shell* get_shell(unsigned i = 0)
    { return i < shells.size() ? shells[i] : nullptr; }

public:  // FIXIT-M make impl private
    std::vector<Shell*> shells;
    std::vector<InspectionPolicy*> inspection_policy;
    std::vector<IpsPolicy*> ips_policy;
    std::vector<NetworkPolicy*> network_policy;
};

//-------------------------------------------------------------------------
// navigator stuff
//-------------------------------------------------------------------------

// FIXIT-L may be inlined at some point; on lockdown for now
// FIXIT-L SO_PUBLIC required because SnortConfig::inline_mode(), etc. uses the function
SO_PUBLIC NetworkPolicy* get_network_policy();
SO_PUBLIC InspectionPolicy* get_inspection_policy();
SO_PUBLIC IpsPolicy* get_ips_policy();

void set_network_policy(NetworkPolicy*);
void set_inspection_policy(InspectionPolicy*);
void set_ips_policy(IpsPolicy*);

void set_policies(struct SnortConfig*, unsigned = 0);
void set_default_policy();

#endif

