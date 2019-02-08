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
// action_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef ACTION_MANAGER_H
#define ACTION_MANAGER_H

// Factory for IpsActions.  Also manages their associated action queue,
// which is just a single response deferred until end of current packet
// processing.

#include "actions/actions.h"
#include "framework/ips_action.h"
#include "framework/module.h"

namespace snort
{
struct ActionApi;
class IpsAction;
struct SnortConfig;
struct Packet;
}

//-------------------------------------------------------------------------

#ifdef PIGLET
struct IpsActionWrapper
{
    IpsActionWrapper(const snort::ActionApi* a, snort::IpsAction* p) :
        api { a }, instance { p } { }

    ~IpsActionWrapper()
    {
        if ( api && instance && api->dtor )
            api->dtor(instance);
    }

    const snort::ActionApi* api;
    snort::IpsAction* instance;
};
#endif

class ActionManager
{
public:
    static void add_plugin(const snort::ActionApi*);
    static void release_plugins();
    static void dump_plugins();

    static void new_config(snort::SnortConfig*);
    static snort::Actions::Type get_action_type(const char*);
    static void delete_config(snort::SnortConfig*);

    static void instantiate(const snort::ActionApi*, snort::Module*, snort::SnortConfig*);

    static void thread_init(snort::SnortConfig*);
    static void thread_reinit(snort::SnortConfig*);
    static void thread_term(snort::SnortConfig*);

    static void reset_queue(snort::Packet*);
    static void queue_reject(snort::SnortConfig*, snort::Packet*);
    static void queue(snort::IpsAction*, snort::Packet*);
    static void execute(snort::Packet*);

#ifdef PIGLET
    static IpsActionWrapper* instantiate(const char*, snort::Module*);
#endif
};

#endif

