//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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
// policy_selector_manager.cc author Ron Dempster <rdempste@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "policy_selector_manager.h"

#include <cassert>
#include <unordered_map>

#include "framework/policy_selector.h"
#include "framework/module.h"
#include "main/snort_config.h"
#include "log/messages.h"
#include "utils/util.h"

using namespace snort;

static std::unordered_map<std::string, const PolicySelectorApi*> s_selectors;

//-------------------------------------------------------------------------

void PolicySelectorManager::add_plugin(const PolicySelectorApi* api)
{
    assert(s_selectors.find(api->base.name) == s_selectors.end());

    s_selectors[api->base.name] = api;
}

void PolicySelectorManager::dump_plugins()
{
    Dumper d("Selectors");

    for (auto& sc : s_selectors)
        d.dump(sc.second->base.name, sc.second->base.version);
}

void PolicySelectorManager::release_plugins()
{
    s_selectors.clear();
}

void PolicySelectorManager::instantiate(const PolicySelectorApi* api, Module* mod, SnortConfig* sc)
{
    assert(sc);
    if (sc->policy_map->get_policy_selector())
    {
        ParseError("Only one selector may be instantiated\n");
        return;
    }
    assert(api);
    sc->policy_map->set_policy_selector(api->ctor(mod));
}

void PolicySelectorManager::print_config(const SnortConfig* sc)
{
    assert(sc);
    const PolicySelector* ps = sc->policy_map->get_policy_selector();
    if (ps)
    {
        LogLabel("Policy Selector");
        std::string name = ps->get_api()->base.name;
        name += ":";
        LogLabel(name.c_str());
        ps->show();
    }
}

