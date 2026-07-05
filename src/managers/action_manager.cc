//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "main/snort_config.h"
#include "packet_io/active.h"
#include "parser/parser.h"

#include "module_manager.h"
#include "framework/parameter.h"
#include "plugin_manager.h"
#include "plug_interface.h"

using namespace snort;
using namespace std;

class ActionClass : public PlugInterface
{
public:
    const ActionApi* api;

    ActionClass(const ActionApi* p) : api(p) { }

    void global_init() override
    {
        if ( api->pinit )
            api->pinit();
    }

    void global_term() override
    {
        if ( api->pterm )
            api->pterm();
    }

    void thread_init() override
    {
        if ( api->tinit )
            api->tinit();
    }

    void thread_term() override
    {
        if ( api->tterm )
            api->tterm();
    }

    void instantiate(Module* mod, SnortConfig* sc, const char*) override
    {
        ActionManager::instantiate(api, mod, sc);
    }
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

using ACTypeList = unordered_map<string, IpsAction::Type>;
using ACPriorityList = map<IpsAction::IpsActionPriority, string, std::greater<int>>;

static ACTypeList s_act_types;
static ACPriorityList s_act_priorities;
static IpsAction::Type s_act_index = 0;

//-------------------------------------------------------------------------
// Main thread operations
//-------------------------------------------------------------------------

// Plugin/Class operations
PlugInterface* ActionManager::get_interface(const ActionApi* api)
{
    s_act_types.emplace(api->base.name, s_act_index++);
    s_act_priorities.emplace(api->priority, api->base.name);
    return new ActionClass(api);
}

std::string ActionManager::get_action_string(IpsAction::Type action)
{
    if ( action < s_act_index )
    {
        auto it = std::find_if(s_act_types.cbegin(), s_act_types.cend(),
            [action](const std::pair<const std::string, IpsAction::Type>& type){ return type.second == action; });
        if ( it != s_act_types.cend())
            return (*it).first;
    }

    return "ERROR";
}

IpsAction::Type ActionManager::get_action_type(const char* s)
{
    auto type = s_act_types.find(s);

    if (type != s_act_types.end())
        return type->second;

    return get_max_action_types();
}

IpsAction::Type ActionManager::get_max_action_types()
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

static ActionClass* get_action_class(const ActionApi* api, IpsActionsConfig* iac)
{
    auto it = std::find_if(iac->clist.cbegin(), iac->clist.cend(),
        [api](const ActionInst &ai){ return ai.cls.api == api; });

    if ( it != iac->clist.cend() )
        return &(*it).cls;

    return static_cast<ActionClass*>(PluginManager::get_interface(api->base.name));
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
        if (!ips)
            ips = get_ips_policy();

        IpsAction::Type idx = rln->mode;

        if (!ips->action[idx])
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

IpsAction* ActionManager::instantiate_action_with_param(const char* action_name, const char* param,
    const char* value, SnortConfig* sc)
{
    ActionClass* cls = static_cast<ActionClass*>(PluginManager::get_interface(action_name));
    if ( !cls )
    {
        ParseError("unknown IPS action '%s'", action_name);
        return nullptr;
    }

    const BaseApi& base = cls->api->base;
    Module* mod = base.mod_ctor ? base.mod_ctor() : nullptr;
    if ( !mod )
    {
        ParseError("IPS action '%s' does not support configuration", action_name);
        return nullptr;
    }

    bool ok = mod->verified_begin(action_name, 0, sc);
    const Parameter* p = Parameter::find(mod->get_parameters(), param);

    if ( ok and !p )
    {
        ParseError("IPS action '%s' has no '%s' parameter", action_name, param);
        ok = false;
    }

    if ( ok )
    {
        Value v(value);
        v.set(p);
        ok = mod->verified_set((std::string(action_name) + "." + param).c_str(), v, sc);
    }

    if ( ok )
        ok = mod->verified_end(action_name, 0, sc);

    IpsAction* act = nullptr;
    if ( ok )
        act = cls->api->ctor(mod);

    if ( base.mod_dtor )
        base.mod_dtor(mod);
    else
        delete mod;

    if ( act )
    {
        sc->ips_actions_config->clist.emplace_back(*cls, act);
        PluginManager::set_instantiated(action_name);
    }

    return act;
}

void ActionManager::initialize_policies(SnortConfig* sc)
{
    for (unsigned i = 0; i < sc->policy_map->ips_policy_count(); i++)
    {
        static IpsPolicy* policy;
        policy = sc->policy_map->get_ips_policy(i);

        if ( !policy )
            continue;

        auto create = [](PlugInterface* pin, void* pv)
        {
            ActionClass* ac = static_cast<ActionClass*>(pin);
            SnortConfig* conf = static_cast<SnortConfig*>(pv);
            ActionManager::instantiate(ac->api, nullptr, conf, policy);
            PluginManager::set_instantiated(ac->api->base.name);
        };

        PluginManager::for_each(PT_IPS_ACTION, create, sc);
    }
}
