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
// ips_actions.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ips_actions.h"

#include "managers/plugin_manager.h"

using namespace snort;

#ifdef STATIC_IPS_ACTIONS
extern const BaseApi* act_react[];
#endif
extern const BaseApi* act_alert[];
extern const BaseApi* act_block[];
extern const BaseApi* act_drop[];
extern const BaseApi* act_file_id[];
extern const BaseApi* act_log[];
extern const BaseApi* act_pass[];
extern const BaseApi* act_reject[];
extern const BaseApi* act_replace[];

void load_actions()
{
#ifdef STATIC_IPS_ACTIONS
    PluginManager::load_plugins(act_react);
#endif
    PluginManager::load_plugins(act_alert);
    PluginManager::load_plugins(act_block);
    PluginManager::load_plugins(act_drop);
    PluginManager::load_plugins(act_file_id);
    PluginManager::load_plugins(act_log);
    PluginManager::load_plugins(act_pass);
    PluginManager::load_plugins(act_reject);
    PluginManager::load_plugins(act_replace);
}

