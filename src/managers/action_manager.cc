//--------------------------------------------------------------------------
// Copyright (C) 2014-2019 Cisco and/or its affiliates. All rights reserved.
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

#include "actions/act_replace.h"
#include "log/messages.h"
#include "main/snort_config.h"
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
    IpsAction* reject = nullptr;
};

using ACList = vector<ActionClass>;

static ACList s_actors;

static THREAD_LOCAL ACList* s_tl_actors = nullptr;

//-------------------------------------------------------------------------
// Main thread operations
//-------------------------------------------------------------------------

// Plugin/Class operations
void ActionManager::add_plugin(const ActionApi* api)
{
    s_actors.emplace_back(api);
}

Actions::Type ActionManager::get_action_type(const char* s)
{
    for ( auto& p : s_actors )
    {
        if ( !strcmp(p.api->base.name, s) )
            return p.api->type;
    }
    return Actions::NONE;
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

void ActionManager::instantiate(const ActionApi* api, Module* mod, SnortConfig* sc)
{
    ActionClass* cls = get_action_class(api, sc->ips_actions_config);
    assert(cls != nullptr);

    IpsAction* act = cls->api->ctor(mod);

    if ( act )
    {
        // Add this instance to the list of those created for this config
        sc->ips_actions_config->clist.emplace_back(*cls, act);

        // FIXIT-M Either you are static or you're not, make a choice.
        // Anyway, if we happen to instantiate an action called reject, cache that for use later.
        if ( !sc->ips_actions_config->reject && !strcmp(act->get_name(), "reject") )
            sc->ips_actions_config->reject = act;

        ListHead* lh = CreateRuleType(sc, api->base.name, api->type);
        assert(lh);
        lh->action = act;
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

void ActionManager::thread_init(SnortConfig* sc)
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

void ActionManager::thread_reinit(SnortConfig* sc)
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

void ActionManager::thread_term(SnortConfig*)
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

void ActionManager::execute(Packet* p)
{
    if ( *p->action )
    {
        (*p->action)->exec(p);
        *p->action = nullptr;
    }
}

void ActionManager::queue(IpsAction* a, Packet* p)
{
    if ( !(*p->action) || a->get_action() > (*p->action)->get_action() )
        *p->action = a;
}

void ActionManager::queue_reject(SnortConfig* sc, Packet* p)
{
    if ( sc->ips_actions_config->reject )
        queue(sc->ips_actions_config->reject, p);
}

void ActionManager::reset_queue(Packet* p)
{
    *p->action = nullptr;
    Replace_ResetQueue();
}

#ifdef PIGLET

//-------------------------------------------------------------------------
// piglet breach
//-------------------------------------------------------------------------

static const ActionApi* find_api(const char* name)
{
    for ( auto actor : s_actors )
        if ( !strcmp(actor.api->base.name, name) )
            return actor.api;

    return nullptr;
}

IpsActionWrapper* ActionManager::instantiate(const char* name, Module* m)
{
    auto api = find_api(name);
    if ( !api || !api->ctor )
        return nullptr;

    auto p = api->ctor(m);
    if ( !p )
        return nullptr;

    return new IpsActionWrapper(api, p);
}

#endif

