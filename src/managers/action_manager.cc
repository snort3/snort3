/*
**  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
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
**
*/
// action_manager.cc author Russ Combs <rucombs@cisco.com>

#include "action_manager.h"

#include <list>
using namespace std;

#include "snort_types.h"
#include "snort.h"
#include "snort_debug.h"
#include "util.h"
#include "module_manager.h"
#include "framework/ips_action.h"
#include "search_engines/search_engines.h"
#include "parser/parser.h"
#include "log/messages.h"
#include "actions/act_replace.h"

typedef list<const ActionApi*> AList;
static AList s_actors;

static IpsAction* s_reject = nullptr;
static THREAD_LOCAL IpsAction* s_action = nullptr;

//-------------------------------------------------------------------------
// engine plugins
//-------------------------------------------------------------------------

void ActionManager::add_plugin(const ActionApi* api)
{
    s_actors.push_back(api);
}

void ActionManager::release_plugins()
{
    s_actors.clear();
}

void ActionManager::dump_plugins()
{
    Dumper d("IPS Actions");

    for ( auto* p : s_actors )
        d.dump(p->base.name, p->base.version);
}

//-------------------------------------------------------------------------

RuleType ActionManager::get_action_type(const char* s)
{
    for ( auto* p : s_actors )
    {
        if ( !strcmp(p->base.name, s) )
            return p->type;
    }
    return RULE_TYPE__NONE;
}

void ActionManager::instantiate(
    const ActionApi* api, Module* m, SnortConfig* sc)
{
    IpsAction* act = api->ctor(m);

    if ( act )
    {
        if ( !s_reject && !strcmp(act->get_name(), "reject") )
            s_reject = act;

        ListHead* lh = CreateRuleType(sc, api->base.name, api->type, 0, nullptr);
        assert(lh);
        lh->action = act;
    }
}

void ActionManager::thread_init(SnortConfig*)
{
    for ( auto* p : s_actors )
        if ( p->tinit )
            p->tinit();
}

void ActionManager::thread_term(SnortConfig*)
{
    for ( auto* p : s_actors )
        if ( p->tterm )
            p->tterm();
}

#if 0
static const ActionApi* get_api(const char* keyword)
{
    for ( auto* p : s_actors )
        if ( !strcasecmp(p->base.name, keyword) )
            return p;

    return nullptr;
}
#endif

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

