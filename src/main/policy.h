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

#ifndef SNORT_POLICY_H
#define SNORT_POLICY_H

// the following policy types are defined:
//
// -- network - for packet handling
// -- inspection - for flow handling
// -- ips - for rule handling

#ifdef HAVE_UUID
#include <uuid.h>
#else
typedef unsigned char uuid_t[16];
#endif

#include <algorithm>
#include <climits>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

#include "framework/data_bus.h"

namespace snort
{
class FilePolicyBase;
class GHash;
class IpsAction;
class PolicySelector;
struct SnortConfig;
}

struct _daq_flow_stats;
struct _daq_pkt_hdr;
struct JSNormConfig;
struct PortTable;
struct vartable_t;
struct sfip_var_t;

#define UNDEFINED_NETWORK_USER_POLICY_ID UINT64_MAX

typedef unsigned int PolicyId;
typedef snort::GHash PortVarTable;

enum PolicyMode
{
    POLICY_MODE__PASSIVE,
    POLICY_MODE__INLINE,
    POLICY_MODE__INLINE_TEST,
    POLICY_MODE__MAX
};

// FIXIT-L split into separate headers

//-------------------------------------------------------------------------
// navigator stuff
//-------------------------------------------------------------------------

struct InspectionPolicy;
struct IpsPolicy;
struct NetworkPolicy;
class Shell;

namespace snort
{
SO_PUBLIC NetworkPolicy* get_network_policy();
NetworkPolicy* get_network_parse_policy();
SO_PUBLIC InspectionPolicy* get_inspection_policy();
SO_PUBLIC IpsPolicy* get_ips_policy();

SO_PUBLIC void set_network_policy(NetworkPolicy*);
void set_network_parse_policy(NetworkPolicy*);
SO_PUBLIC void set_inspection_policy(InspectionPolicy*);
SO_PUBLIC void set_ips_policy(IpsPolicy*);

SO_PUBLIC NetworkPolicy* get_default_network_policy(const snort::SnortConfig*);
// Based on currently set network policy
SO_PUBLIC InspectionPolicy* get_user_inspection_policy(unsigned policy_id);

SO_PUBLIC IpsPolicy* get_ips_policy(const snort::SnortConfig*, unsigned i = 0);
// Based on currently set network policy
SO_PUBLIC IpsPolicy* get_default_ips_policy(const snort::SnortConfig*);
SO_PUBLIC IpsPolicy* get_user_ips_policy(const snort::SnortConfig*, unsigned policy_id);
SO_PUBLIC IpsPolicy* get_empty_ips_policy(const snort::SnortConfig*);
}

void set_network_policy(unsigned = 0);
void set_inspection_policy(unsigned = 0);
void set_ips_policy(const snort::SnortConfig*, unsigned = 0);

void set_policies(const snort::SnortConfig*, Shell*);
void set_default_policy(const snort::SnortConfig*);
void select_default_policy(const _daq_pkt_hdr&, const snort::SnortConfig*);
void select_default_policy(const _daq_flow_stats&, const snort::SnortConfig*);

bool only_inspection_policy();
bool only_ips_policy();

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

//-------------------------------------------------------------------------
// inspection stuff
//-------------------------------------------------------------------------

struct InspectionPolicy
{
public:
    InspectionPolicy(PolicyId = 0);
    InspectionPolicy(InspectionPolicy* old_inspection_policy);
    ~InspectionPolicy();

    void configure();

public:
    PolicyId policy_id = 0;
    PolicyMode policy_mode = POLICY_MODE__MAX;
    uint64_t user_policy_id = 0;
    uuid_t uuid{};

    struct FrameworkPolicy* framework_policy;
    snort::DataBus dbus;
    bool cloned;

    JSNormConfig* jsn_config = nullptr;

private:
    void init(InspectionPolicy* old_inspection_policy);
};

//-------------------------------------------------------------------------
// Network stuff
//-------------------------------------------------------------------------

class FilePolicy;
class FileRule;
struct IpsPolicy;

struct NetworkPolicy
{
public:
    NetworkPolicy(PolicyId = 0, PolicyId default_ips_id = 0);
    NetworkPolicy(NetworkPolicy*, const char*);
    ~NetworkPolicy();

    InspectionPolicy* get_inspection_policy(unsigned i = 0)
    { return i < inspection_policy.size() ? inspection_policy[i] : nullptr; }
    unsigned inspection_policy_count()
    { return inspection_policy.size(); }
    InspectionPolicy* get_user_inspection_policy(unsigned user_id);
    void set_user_inspection(InspectionPolicy* p)
    { user_inspection[p->user_policy_id] = p; }

    IpsPolicy* get_default_ips_policy(const snort::SnortConfig* sc)
    { return snort::get_ips_policy(sc, default_ips_policy_id); }

    void add_file_policy_rule(FileRule& file_rule);
    snort::FilePolicyBase* get_base_file_policy() const;
    FilePolicy* get_file_policy() const;

    bool checksum_drops(uint16_t codec_cksum_err_flag)
    { return (checksum_drop & codec_cksum_err_flag) != 0; }

    bool ip_checksums()
    { return (checksum_eval & CHECKSUM_FLAG__IP) != 0; }

    bool udp_checksums()
    { return (checksum_eval & CHECKSUM_FLAG__UDP) != 0; }

    bool tcp_checksums()
    { return (checksum_eval & CHECKSUM_FLAG__TCP) != 0; }

    bool icmp_checksums()
    { return (checksum_eval & CHECKSUM_FLAG__ICMP) != 0; }

protected:
    FilePolicy* file_policy;

public:
    struct TrafficPolicy* traffic_policy;
    snort::DataBus dbus;

    std::vector<InspectionPolicy*> inspection_policy;
    std::unordered_map<uint64_t, InspectionPolicy*> user_inspection;

    PolicyId policy_id = 0;
    uint64_t user_policy_id = 0;
    PolicyId default_ips_policy_id = 0;

    // minimum possible (allows all but errors to pass by default)
    uint8_t min_ttl = 1;
    uint8_t new_ttl = 5;

    uint32_t checksum_eval = CHECKSUM_FLAG__ALL | CHECKSUM_FLAG__DEF;
    uint32_t checksum_drop = CHECKSUM_FLAG__DEF;
    uint32_t normal_mask = 0;
    bool cloned = false;

private:
    void init(NetworkPolicy*, const char*);
};

//-------------------------------------------------------------------------
// detection stuff
//-------------------------------------------------------------------------

struct IpsPolicy
{
public:
    enum Enable : uint8_t { DISABLED, ENABLED, INHERIT_ENABLE };

    IpsPolicy(PolicyId = 0);
    ~IpsPolicy();

public:
    PolicyId policy_id;
    uint64_t user_policy_id = 0;
    uuid_t uuid{};

    PolicyMode policy_mode = POLICY_MODE__MAX;
    bool enable_builtin_rules;
    int rules_loaded = 0;
    int rules_shared = 0;

    std::string includer;
    std::string include;

    std::string rules;
    std::string states;

    uint32_t var_id;

    struct VarEntry* var_table;
    vartable_t* ip_vartable;

    /* The portobjects in these are attached to rtns and used during runtime */
    PortVarTable* portVarTable;     /* named entries, uses a hash table */
    PortTable* nonamePortVarTable;  /* un-named entries */

    Enable default_rule_state = INHERIT_ENABLE;

    bool obfuscate_pii;

    std::string action_override;
    std::map<std::string, std::string> action_map;

    // Holds all plugin actions associated with this policy
    std::vector<snort::IpsAction*> action;
};

//-------------------------------------------------------------------------
// binding stuff
//-------------------------------------------------------------------------

struct PolicyTuple
{
    InspectionPolicy* inspection = nullptr;
    IpsPolicy* ips = nullptr;
    NetworkPolicy* network = nullptr;
    NetworkPolicy* network_parse = nullptr;

    PolicyTuple(InspectionPolicy* ins_pol, IpsPolicy* ips_pol, NetworkPolicy* net_pol,
        NetworkPolicy* net_parse) :
        inspection(ins_pol), ips(ips_pol), network(net_pol), network_parse(net_parse)
    { }
};

struct GlobalInspectorPolicy;
class SingleInstanceInspectorPolicy;

class PolicyMap
{
public:
    PolicyMap(PolicyMap* old_map = nullptr, const char* exclude_name = nullptr);
    ~PolicyMap();

    InspectionPolicy* add_inspection_shell(Shell*);
    IpsPolicy* add_ips_shell(Shell*);
    std::shared_ptr<PolicyTuple> add_shell(Shell*, NetworkPolicy*);
    std::shared_ptr<PolicyTuple> get_policies(Shell* sh);

    Shell* get_shell(unsigned i = 0)
    { return i < shells.size() ? shells[i] : nullptr; }

    bool setup_network_policies();

    void set_user_ips(IpsPolicy* p)
    { user_ips[p->user_policy_id] = p; }

    NetworkPolicy* get_user_network(uint64_t user_id) const;

    IpsPolicy* get_user_ips(uint64_t user_id)
    {
        auto it = user_ips.find(user_id);
        return it == user_ips.end() ? nullptr : it->second;
    }

    NetworkPolicy* get_network_policy(unsigned i = 0)
    { return i < network_policy.size() ? network_policy[i] : nullptr; }
    unsigned network_policy_count()
    { return network_policy.size(); }

    IpsPolicy* get_ips_policy(unsigned i = 0)
    { return i < ips_policy.size() ? ips_policy[i] : nullptr; }
    unsigned ips_policy_count()
    { return ips_policy.size(); }
    IpsPolicy* get_empty_ips()
    { return empty_ips_policy; }

    unsigned shells_count()
    { return shells.size(); }

    void set_cloned(bool state)
    { cloned = state; }

    snort::PolicySelector* get_policy_selector() const
    { return selector; }

    void set_policy_selector(snort::PolicySelector* new_selector)
    { selector = new_selector; }

    SingleInstanceInspectorPolicy* get_file_id()
    { return file_id; }

    SingleInstanceInspectorPolicy* get_flow_tracking()
    { return flow_tracking; }

    GlobalInspectorPolicy* get_global_inspector_policy()
    { return global_inspector_policy; }

    const Shell* get_shell_by_policy(unsigned id) const
    {
        auto it = std::find_if(std::begin(shell_map), std::end(shell_map),
            [=](auto&& p) { return p.second->ips and p.second->ips->policy_id == id; });

        return (it == std::end(shell_map)) ? nullptr : it->first;
    }

    bool get_inspector_tinit_complete(unsigned instance_id) const
    { return inspector_tinit_complete[instance_id]; }

    void set_inspector_tinit_complete(unsigned instance_id, bool val)
    { inspector_tinit_complete[instance_id] = val; }

private:
    void clone(PolicyMap *old_map, const char* exclude_name);
    bool set_user_network(NetworkPolicy* p);

    std::vector<Shell*> shells;
    std::vector<NetworkPolicy*> network_policy;
    std::vector<IpsPolicy*> ips_policy;
    IpsPolicy* empty_ips_policy;

    std::unordered_map<Shell*, std::shared_ptr<PolicyTuple>> shell_map;
    std::unordered_map<uint64_t, NetworkPolicy*> user_network;
    std::unordered_map<uint64_t, IpsPolicy*> user_ips;

    snort::PolicySelector* selector = nullptr;
    SingleInstanceInspectorPolicy* file_id;
    SingleInstanceInspectorPolicy* flow_tracking;
    GlobalInspectorPolicy* global_inspector_policy;

    bool* inspector_tinit_complete;
    bool cloned = false;
};

#endif

