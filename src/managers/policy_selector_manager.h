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
// policy_selector_manager.h author Ron Dempster <rdempste@cisco.com>

#ifndef POLICY_SELECTOR_MANAGER_H
#define POLICY_SELECTOR_MANAGER_H

// Policy selectors are used in a multi-tenant configuration to select all policies
// based on layer 1 criteria. This is the manager for a given policy selector.
// Only one selector is permitted in the configuration and it must be at the top level.

namespace snort
{
struct PolicySelectorApi;
class Module;
struct SnortConfig;
}

//-------------------------------------------------------------------------

class PolicySelectorManager
{
public:
    static void add_plugin(const snort::PolicySelectorApi* api);
    static void dump_plugins();
    static void release_plugins();

    static void instantiate(const snort::PolicySelectorApi*, snort::Module*, snort::SnortConfig*);
    static void print_config(const snort::SnortConfig*);
};

#endif

