//--------------------------------------------------------------------------
// Copyright (C) 2021-2025 Cisco and/or its affiliates. All rights reserved.
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

#include "policy_selectors.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "managers/plugin_manager.h"

using namespace snort;

extern const BaseApi* ps_address_space_selector;
extern const BaseApi* ps_tenant_selector;

static const BaseApi* policy_selectors[] =
{
    ps_address_space_selector,
    ps_tenant_selector,
    nullptr
};

void load_policy_selectors()
{
    PluginManager::load_plugins(policy_selectors);
}

