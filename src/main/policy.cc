//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "detection/detection_engine.h"
#include "file_api/file_policy.h"
#include "framework/ips_action.h"
#include "framework/policy_selector.h"
#include "js_norm/js_config.h"
#include "log/messages.h"
#include "main/thread_config.h"
#include "managers/codec_manager.h"
#include "managers/inspector_manager.h"
#include "parser/parse_conf.h"
#include "parser/vars.h"
#include "ports/port_var_table.h"
#include "pub_sub/intrinsic_event_ids.h"

#include "modules.h"
#include "shell.h"
#include "snort_config.h"

using namespace snort;

//-------------------------------------------------------------------------
// traffic policy
//-------------------------------------------------------------------------

NetworkPolicy::NetworkPolicy(PolicyId id, PolicyId default_ips_id)
    : policy_id(id), default_ips_policy_id(default_ips_id)
{
    file_policy = new FilePolicy;
    traffic_group = InspectorManager::create_traffic_group();
    cd_mgr = new CodecManager;
}

NetworkPolicy::~NetworkPolicy()
{
    FilePolicyBase::delete_file_policy(file_policy);
    delete cd_mgr;

    for ( auto p : inspection_policy )
        delete p;

    InspectorManager::delete_group(traffic_group);
    inspection_policy.clear();
}

FilePolicyBase* NetworkPolicy::get_base_file_policy() const
{ return file_policy; }
FilePolicy* NetworkPolicy::get_file_policy() const
{ return file_policy; }

void NetworkPolicy::add_file_policy_rule(FileRule& file_rule)
{ file_policy->add_file_id(file_rule); }

void NetworkPolicy::setup_inspection_policies()
{
    std::for_each(inspection_policy.begin(), inspection_policy.end(),
        [this](InspectionPolicy* ip){ set_user_inspection(ip); });
}

InspectionPolicy* NetworkPolicy::get_user_inspection_policy(uint64_t user_id) const
{
    auto it = user_inspection.find(user_id);
    return it == user_inspection.end() ? nullptr : it->second;
}

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
    service_group = InspectorManager::create_service_group();
}

InspectionPolicy::~InspectionPolicy()
{
    InspectorManager::delete_group(service_group);
    delete jsn_config;
}

void InspectionPolicy::configure()
{
    dbus.subscribe(intrinsic_pub_key, IntrinsicEventIds::ALT_PACKET, new AltPktHandler);
}

//-------------------------------------------------------------------------
// detection policy
//-------------------------------------------------------------------------

IpsPolicy::IpsPolicy(PolicyId id) : action(IpsAction::get_max_types(), nullptr)
{
    policy_id = id;
    policy_mode = POLICY_MODE__MAX;

    var_table = nullptr;

    var_id = 1;
    ip_vartable = sfvt_alloc_table();
    portVarTable = PortVarTableCreate();
    nonamePortVarTable = PortTableNew();

    enable_builtin_rules = false;
    obfuscate_pii = true;
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

void IpsPolicy::update_user_policy_id()
{
    if ( !user_policy_id )
        user_policy_id = 1;
}

//-------------------------------------------------------------------------
// policy map
//-------------------------------------------------------------------------

PolicyMap::PolicyMap()
{
    global_group = InspectorManager::create_global_group();
    add_shell(new Shell(nullptr, true), nullptr);
    empty_ips_policy = new IpsPolicy(ips_policy.size());
    ips_policy.push_back(empty_ips_policy);

    set_network_policy(network_policy[0]);
    set_network_parse_policy(network_policy[0]);
    set_inspection_policy(network_policy[0]->get_inspection_policy(0));
    set_ips_policy(ips_policy[0]);
}

PolicyMap::~PolicyMap()
{
    for ( auto p : shells )
        delete p;

    for ( auto p : ips_policy )
        delete p;

    for ( auto p : network_policy )
        delete p;

    PolicySelector::free_policy_selector(selector);
    InspectorManager::delete_group(global_group);

    shells.clear();
    ips_policy.clear();
    network_policy.clear();
    shell_map.clear();
}

bool PolicyMap::setup_network_policies()
{
    return std::none_of(network_policy.begin(), network_policy.end(),
        [this](NetworkPolicy* np){ return !set_user_network(np); });
}

InspectionPolicy* PolicyMap::add_inspection_shell(Shell* sh)
{
    NetworkPolicy* np = get_network_parse_policy();
    assert(np);
    unsigned idx = np->inspection_policy_count();
    InspectionPolicy* ip = new InspectionPolicy(idx);

    shells.push_back(sh);
    np->inspection_policy.push_back(ip);
    shell_map[sh] = std::make_shared<PolicyTuple>(ip, nullptr, nullptr, np);

    return ip;
}

IpsPolicy* PolicyMap::add_ips_shell(Shell* sh)
{
    unsigned idx = ips_policy.size();
    IpsPolicy* p = new IpsPolicy(idx);

    shells.push_back(sh);
    ips_policy.push_back(p);
    shell_map[sh] = std::make_shared<PolicyTuple>(nullptr, p, nullptr, get_network_parse_policy());

    return p;
}

std::shared_ptr<PolicyTuple> PolicyMap::add_shell(Shell* sh, NetworkPolicy* np_in)
{
    shells.push_back(sh);
    IpsPolicy* ips = new IpsPolicy(ips_policy.size());
    ips_policy.push_back(ips);
    NetworkPolicy* np;
    if (!np_in)
    {
        np_in = np = new NetworkPolicy(network_policy.size(), ips->policy_id);
        network_policy.push_back(np);
    }
    else
    {
        np = np_in;
        np_in = nullptr;
    }
    InspectionPolicy* ip = new InspectionPolicy(np->inspection_policy_count());
    np->inspection_policy.push_back(ip);
    return shell_map[sh] =
        std::make_shared<PolicyTuple>(ip, ips, np_in, np);
}

std::shared_ptr<PolicyTuple> PolicyMap::get_policies(Shell* sh)
{
    const auto& pt = shell_map.find(sh);

    return pt == shell_map.end() ? nullptr : pt->second;
}

NetworkPolicy* PolicyMap::get_user_network(uint64_t user_id) const
{
    auto it = user_network.find(user_id);
    NetworkPolicy* np = (it == user_network.end()) ? nullptr : it->second;
    return np;
}

bool PolicyMap::set_user_network(NetworkPolicy* p)
{
    NetworkPolicy* current_np = get_user_network(p->user_policy_id);
    if (current_np)
        return p == current_np;
    user_network[p->user_policy_id] = p;
    p->setup_inspection_policies();
    return true;
}

const Shell* PolicyMap::get_shell_by_file(const std::string& fn) const
{
    for ( const auto* sh : shells )
    {
        if ( fn == sh->get_file() )
            return sh;
    }
    return nullptr;
}

//-------------------------------------------------------------------------
// policy nav
//-------------------------------------------------------------------------

static THREAD_LOCAL NetworkPolicy* s_network_policy = nullptr;
static THREAD_LOCAL NetworkPolicy* s_network_parse_policy = nullptr;
static THREAD_LOCAL InspectionPolicy* s_inspection_policy = nullptr;
static THREAD_LOCAL IpsPolicy* s_detection_policy = nullptr;

namespace snort
{
NetworkPolicy* get_network_policy()
{ return s_network_policy; }

NetworkPolicy* get_network_parse_policy()
{ return s_network_parse_policy; }

InspectionPolicy* get_inspection_policy()
{ return s_inspection_policy; }

IpsPolicy* get_ips_policy()
{ return s_detection_policy; }

void set_network_parse_policy(NetworkPolicy* p)
{ s_network_parse_policy = p; }

void set_network_policy(NetworkPolicy* p)
{ s_network_policy = p; }

void set_inspection_policy(InspectionPolicy* p)
{ s_inspection_policy = p; }

void set_ips_policy(IpsPolicy* p)
{ s_detection_policy = p; }

InspectionPolicy* get_user_inspection_policy(uint64_t policy_id)
{
    NetworkPolicy* np = get_network_policy();
    assert(np);
    return np->get_user_inspection_policy(policy_id);
}

NetworkPolicy* get_default_network_policy(const SnortConfig* sc)
{ return sc->policy_map->get_network_policy(0); }

IpsPolicy* get_ips_policy(const SnortConfig* sc, unsigned i)
{
    return sc && i < sc->policy_map->ips_policy_count() ?
        sc->policy_map->get_ips_policy(i) : nullptr;
}

IpsPolicy* get_default_ips_policy(const snort::SnortConfig* sc)
{
    NetworkPolicy* np = get_network_policy();
    assert(np);
    return np->get_default_ips_policy(sc);
}

IpsPolicy* get_user_ips_policy(const SnortConfig* sc, unsigned policy_id)
{ return sc->policy_map->get_user_ips(policy_id); }

IpsPolicy* get_empty_ips_policy(const SnortConfig* sc)
{ return sc->policy_map->get_empty_ips(); }
} // namespace snort

void set_network_policy(unsigned i)
{
    PolicyMap* pm = SnortConfig::get_conf()->policy_map;
    NetworkPolicy* np = pm->get_network_policy(i);
    if ( np )
        set_network_policy(np);
}

void set_inspection_policy(unsigned i)
{
    NetworkPolicy* np = get_network_policy();
    if (np)
    {
        InspectionPolicy* ip = np->get_inspection_policy(i);
        if (ip)
            set_inspection_policy(ip);
    }
}

void set_ips_policy(const snort::SnortConfig* sc, unsigned i)
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
    NetworkPolicy* np = get_default_network_policy(sc);
    set_network_policy(np);
    set_inspection_policy(np->get_inspection_policy(0));
    set_ips_policy(get_ips_policy(sc, 0));
}

void select_default_policy(const _daq_pkt_hdr& pkthdr, const SnortConfig* sc)
{
    PolicySelector* ps = sc->policy_map->get_policy_selector();
    if (!ps || !ps->select_default_policies(pkthdr, sc))
        set_default_policy(sc);
}

void select_default_policy(const _daq_flow_stats& stats, const snort::SnortConfig* sc)
{
    PolicySelector* ps = sc->policy_map->get_policy_selector();
    if (!ps || !ps->select_default_policies(stats, sc))
        set_default_policy(sc);
}

bool only_inspection_policy()
{ return get_inspection_policy() && !get_ips_policy() && !get_network_policy(); }

bool only_ips_policy()
{ return get_ips_policy() && !get_inspection_policy() && !get_network_policy(); }

