//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#include "framework/ips_action.h"
#include "framework/module.h"

namespace snort
{
struct ActionApi;
struct SnortConfig;
struct Packet;
}

struct IpsPolicy;

//-------------------------------------------------------------------------

class ActionManager
{
public:
    static void add_plugin(const snort::ActionApi*);
    static void release_plugins();
    static void dump_plugins();

    static void new_config(snort::SnortConfig*);
    static void delete_config(snort::SnortConfig*);

    static void instantiate(const snort::ActionApi*, snort::Module*,
            snort::SnortConfig*, IpsPolicy* ips = nullptr );
    static void initialize_policies(snort::SnortConfig*);

    static std::string get_action_string(snort::IpsAction::Type);
    static snort::IpsAction::Type get_action_type(const char*);
    static snort::IpsAction::Type get_max_action_types();
    static std::string get_action_priorities(bool);

    static void thread_init(const snort::SnortConfig*);
    static void thread_reinit(const snort::SnortConfig*);
    static void thread_term();
};

#endif

