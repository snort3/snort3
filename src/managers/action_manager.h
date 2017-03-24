//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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
// action_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef ACTION_MANAGER_H
#define ACTION_MANAGER_H

// Factory for IpsActions.  Also manages their associated action queue,
// which is just a single response deferred until end of current packet
// processing.

#include "actions/actions.h"
#include "framework/ips_action.h"
#include "framework/module.h"

#ifdef PIGLET
#include "framework/ips_action.h"
#endif

struct ActionApi;
class IpsAction;
struct SnortConfig;
struct Packet;

//-------------------------------------------------------------------------

#ifdef PIGLET
struct IpsActionWrapper
{
    IpsActionWrapper(const ActionApi* a, IpsAction* p) :
        api { a }, instance { p } { }

    ~IpsActionWrapper()
    {
        if ( api && instance && api->dtor )
            api->dtor(instance);
    }

    const ActionApi* api;
    IpsAction* instance;
};
#endif

class ActionManager
{
public:
    static void add_plugin(const ActionApi*);
    static void release_plugins();
    static void dump_plugins();

    static RuleType get_action_type(const char*);

    static void instantiate(const ActionApi*, Module*, SnortConfig*);

    static void thread_init(SnortConfig*);
    static void thread_term(SnortConfig*);

    static void reset_queue();
    static void queue_reject(const Packet*);
    static void queue(IpsAction*);
    static void execute(Packet*);

#ifdef PIGLET
    static IpsActionWrapper* instantiate(const char*, Module*);
#endif
};

#endif

