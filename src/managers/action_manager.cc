//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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
// action_manager.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "action_manager.h"

#include <vector>

#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "packet_io/active.h"
#include "parser/parser.h"

using namespace snort;
using namespace std;

struct ActionClass
{
    const ActionApi* api;
    bool initialized = false;   // In the context of the main thread, this means that api.pinit()
                                // has been called.  In the packet thread, it means that api.tinit()
                                // has been called.

    ActionClass(const ActionApi* p) : api(p) { }
};

struct ActionInst
{
    ActionClass& cls;
    IpsAction* act;

    ActionInst(ActionClass& cls, IpsAction* act) : cls(cls), act(act) { }
};

struct IpsActionsConfig
{
    vector<ActionInst> clist;
};

using ACList = vector<ActionClass>;
using ACTypeList = unordered_map<string, Actions::Type>;
using ACPriorityList = map<IpsAction::IpsActionPriority, string, std::greater<int>>;

static ACList s_actors;
static ACTypeList s_act_types;
static ACPriorityList s_act_priorities;
static Actions::Type s_act_index = 0;

static THREAD_LOCAL ACList* s_tl_actors = nullptr;

//-------------------------------------------------------------------------
// Main thread operations
//-------------------------------------------------------------------------

// Plugin/Class operations
void ActionManager::add_plugin(const ActionApi* api)
{
    s_actors.emplace_back(api);
    s_act_types.emplace(api->base.name, s_act_index++);
    s_act_priorities.emplace(api->priority, api->base.name);
}

std::string ActionManager::get_action_string(Actions::Type action)
{
    if ( action < s_act_index )
    {
        for ( const auto& type : s_act_types )
        {
            if ( type.second == action )
                return type.first;
        }
    }

    return "ERROR";
}

Actions::Type ActionManager::get_action_type(const char* s)
{
    auto type = s_act_types.find(s);

    if (type != s_act_types.end())
        return type->second;

    return get_max_action_types();
}

Actions::Type ActionManager::get_max_action_types()
{
    return s_act_index;
}

std::string ActionManager::get_action_priorities(bool alert_before_pass)
{
    std::string priorities;

    for (auto iter = s_act_priorities.begin(); iter != s_act_priorities.end(); )
    {
        if ( alert_before_pass )
        {
            if ( iter->second == "pass" )
            {
                iter++;
                continue;
            }
            else if ( iter->second == "alert" )
            {
                priorities += "alert pass ";
                iter++;
                continue;
            }
        }

        priorities += iter->second;

        if ( ++iter != s_act_priorities.end() )
            priorities += " ";
    }

    return priorities;
}

void ActionManager::dump_plugins()
{
    Dumper d("IPS Actions");

    for ( auto& p : s_actors )
        d.dump(p.api->base.name, p.api->base.version);
}

void ActionManager::release_plugins()
{
    for ( auto& p : s_actors )
    {
        if ( p.api->pterm )
            p.api->pterm();
    }
    s_actors.clear();
}

static ActionClass* get_action_class(const ActionApi* api, IpsActionsConfig* iac)
{
    for ( auto& ai : iac->clist )
    {
        if ( ai.cls.api == api )
            return &ai.cls;
    }

    for ( auto& ac : s_actors )
    {
        if ( ac.api == api )
        {
            if ( !ac.initialized )
            {
                if ( ac.api->pinit )
                    ac.api->pinit();
                ac.initialized = true;
            }
            return &ac;
        }
    }

    return nullptr;
}

// Config operations
void ActionManager::new_config(SnortConfig* sc)
{
    sc->ips_actions_config = new IpsActionsConfig;
}

void ActionManager::delete_config(SnortConfig* sc)
{
    if (!sc->ips_actions_config)
        return;

    // Delete all IPS action instances that were created as part of this configuration
    for (auto& ia : sc->ips_actions_config->clist)
        ia.cls.api->dtor(ia.act);

    delete sc->ips_actions_config;
    sc->ips_actions_config = nullptr;
}

void ActionManager::instantiate(const ActionApi* api, Module* mod, SnortConfig* sc, IpsPolicy* ips)
{
    ActionClass* cls = get_action_class(api, sc->ips_actions_config);

    assert(cls != nullptr);

    IpsAction* act = cls->api->ctor(mod);

    if ( act )
    {

        RuleListNode* rln = CreateRuleType(sc, api->base.name, get_action_type(api->base.name));

        // The plugin actions (e.g. reject, react, etc.) are per policy, per mode.
        // At logging time, they have to be retrieved the way we store them here.
        if ( !ips )
            ips = get_ips_policy();

        Actions::Type idx = rln->mode;
        if (ips->action[idx] == nullptr)
        {
            ips->action[idx] = act;
            // Add this instance to the list of those created for this config
            sc->ips_actions_config->clist.emplace_back(*cls, act);
        }
        else
        {
            cls->api->dtor(act);
        }
    }
}

void ActionManager::initialize_policies(SnortConfig* sc)
{
    for (unsigned i = 0; i < sc->policy_map->ips_policy_count(); i++)
    {
        auto policy = sc->policy_map->get_ips_policy(i);

        if ( !policy )
            continue;

        for ( auto actor : s_actors )
            ActionManager::instantiate(actor.api, nullptr, sc, policy);
    }
}

//-------------------------------------------------------------------------
// Packet thread operations
//-------------------------------------------------------------------------
static ActionClass& get_thread_local_action_class(const ActionApi* api)
{
    for ( ActionClass& p : *s_tl_actors )
    {
        if ( p.api == api )
            return p;
    }
    s_tl_actors->emplace_back(api);
    return s_tl_actors->back();
}

void ActionManager::thread_init(const SnortConfig* sc)
{
    // Initial build out of this thread's configured plugin registry
    s_tl_actors = new ACList;
    for ( auto& p : sc->ips_actions_config->clist )
    {
        ActionClass& tlac = get_thread_local_action_class(p.cls.api);
        if ( tlac.api->tinit )
            tlac.api->tinit();
        tlac.initialized = true;
    }
}

void ActionManager::thread_reinit(const SnortConfig* sc)
{
    // Update this thread's configured plugin registry with any newly configured inspectors
    for ( auto& p : sc->ips_actions_config->clist )
    {
        ActionClass& tlac = get_thread_local_action_class(p.cls.api);
        if (!tlac.initialized)
        {
            if ( tlac.api->tinit )
                tlac.api->tinit();
            tlac.initialized = true;
        }
    }
    Active::thread_init(sc);
}

void ActionManager::thread_term()
{
    if (s_tl_actors)
    {
        // Call tterm for every IPS action plugin ever configured during the lifetime of this thread
        for ( auto& p : *s_tl_actors )
        {
            if ( p.api->tterm )
                p.api->tterm();
        }
        delete s_tl_actors;
        s_tl_actors = nullptr;
    }
}

