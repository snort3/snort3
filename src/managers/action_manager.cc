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

typedef list<const ActionApi*> AList;
static AList s_actors;

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
        ListHead* lh = CreateRuleType(sc, api->base.name, api->type, 0, nullptr);
        assert(lh);
        lh->action = act;
    }
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

void ActionManager::execute(Packet*)
{ }

