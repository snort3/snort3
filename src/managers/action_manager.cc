//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include <list>

#include "actions/act_replace.h"
#include "log/messages.h"
#include "packet_io/active.h"
#include "parser/parser.h"

using namespace snort;
using namespace std;

struct Actor
{
    const ActionApi* api;
    IpsAction* act;

    Actor(const ActionApi* p)
    { api = p; act = nullptr; }
};

typedef list<Actor> AList;
static AList s_actors;

static IpsAction* s_reject = nullptr;
static THREAD_LOCAL IpsAction* s_action = nullptr;

//-------------------------------------------------------------------------
// action plugins
//-------------------------------------------------------------------------

void ActionManager::add_plugin(const ActionApi* api)
{
    Actor a(api);

    if ( api->pinit )
        api->pinit();

    s_actors.push_back(a);
}

void ActionManager::release_plugins()
{
    for ( auto& p : s_actors )
    {
        p.api->dtor(p.act);

        if ( p.api->pterm )
            p.api->pterm();
    }
    s_actors.clear();
}

void ActionManager::dump_plugins()
{
    Dumper d("IPS Actions");

    for ( auto& p : s_actors )
        d.dump(p.api->base.name, p.api->base.version);
}

static void store(const ActionApi* api, IpsAction* act)
{
    for ( auto& p : s_actors )
        if ( p.api == api )
        {
            //assert(!p.act);  FIXIT-H memory leak on reload; move to SnortConfig?
            p.act = act;
            break;
        }
}

//-------------------------------------------------------------------------

Actions::Type ActionManager::get_action_type(const char* s)
{
    for ( auto& p : s_actors )
    {
        if ( !strcmp(p.api->base.name, s) )
            return p.api->type;
    }
    return Actions::NONE;
}

void ActionManager::instantiate(
    const ActionApi* api, Module* m, SnortConfig* sc)
{
    IpsAction* act = api->ctor(m);

    if ( act )
    {
        if ( !s_reject && !strcmp(act->get_name(), "reject") )
            s_reject = act;

        ListHead* lh = CreateRuleType(sc, api->base.name, api->type);
        assert(lh);
        lh->action = act;

        store(api, act);
    }
}

void ActionManager::thread_init(SnortConfig*)
{
    for ( auto& p : s_actors )
        if ( p.api->tinit )
            p.api->tinit();
}

void ActionManager::thread_term(SnortConfig*)
{
    for ( auto& p : s_actors )
        if ( p.api->tterm )
            p.api->tterm();
}

void ActionManager::execute(Packet* p)
{
    if ( s_action )
    {
        s_action->exec(p);
        s_action = nullptr;
    }
}

void ActionManager::queue(IpsAction* a)
{
    if ( !s_action || a->get_action() > s_action->get_action() )
        s_action = a;
}

void ActionManager::queue_reject()
{
    if ( s_reject )
        queue(s_reject);
}

void ActionManager::reset_queue()
{
    s_action = nullptr;
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

