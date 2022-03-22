//--------------------------------------------------------------------------
// Copyright (C) 2021-2022 Cisco and/or its affiliates. All rights reserved.
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
// address_space_selector_module.cc author Ron Dempster <rdempste@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "address_space_selector_module.h"

#include "log/messages.h"
#include "main/shell.h"
#include "main/snort_config.h"
#include "managers/module_manager.h"
#include "policy_selectors/parse_int_set.h"

using namespace snort;
using namespace std;

THREAD_LOCAL PolicySelectStats address_space_select_stats;

static const PegInfo select_pegs[] =
{
    { CountType::SUM, "packets", "packets evaluated" },
    { CountType::SUM, "no_match", "selection evaluations that had no matches" },
    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// selector module
//-------------------------------------------------------------------------

static const Parameter selector_when_params[] =
{
    { "addr_spaces", Parameter::PT_STRING, nullptr, nullptr,
      "list of address space IDs" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter selector_use_params[] =
{
    { "file", Parameter::PT_STRING, nullptr, nullptr,
      "use configuration in given file" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "addr_spaces", Parameter::PT_STRING, nullptr, nullptr,
      "list of address space IDs to match" },

    { "file", Parameter::PT_STRING, nullptr, nullptr,
      "use configuration in given file" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

AddressSpaceSelectorModule::AddressSpaceSelectorModule() : Module(ADDRESS_SPACE_SELECT_NAME, ADDRESS_SPACE_SELECT_HELP, s_params, true)
{ }

AddressSpaceSelectorModule::~AddressSpaceSelectorModule()
{
    policy_selections.clear();
    selection.clear();
}

ProfileStats* AddressSpaceSelectorModule::get_profile() const
{ return &address_space_selectPerfStats; }

void AddressSpaceSelectorModule::add_policy_file(const char* name)
{ policy_filename = name; }

bool AddressSpaceSelectorModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, ADDRESS_SPACE_SELECT_NAME) )
    {
        selection.clear();
        policy_filename.clear();
    }

    return true;
}

bool AddressSpaceSelectorModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("addr_spaces") )
    {
        if (!parse_int_set<uint32_t>(v, selection.addr_spaces))
            return false;
    }

    // use
    else if ( v.is("file") )
        add_policy_file(v.get_string());

    return true;
}

bool AddressSpaceSelectorModule::end(const char* fqn, int idx, SnortConfig* sc)
{
    if ( !strcmp(fqn, ADDRESS_SPACE_SELECT_NAME) && idx )
    {
        // Use validation
        if ( policy_filename.empty() )
        {
            ParseError("Missing policy file name");
            return false;
        }

        Shell* sh = new Shell(policy_filename.c_str());
        auto policies = sc->policy_map->add_shell(sh, nullptr);
        selection.use.network_index = policies->network->policy_id;
        selection.use.inspection_index = policies->inspection->policy_id;
        selection.use.ips_index = policies->ips->policy_id;

        // Store the policy filename for verbose output
        selection.use.name = policy_filename;

        commit_policy_selection();
    }
    return true;
}

void AddressSpaceSelectorModule::commit_policy_selection()
{ policy_selections.emplace_back(selection); }

vector<AddressSpaceSelection>& AddressSpaceSelectorModule::get_policy_selections()
{ return policy_selections; }

const PegInfo* AddressSpaceSelectorModule::get_pegs() const
{ return select_pegs; }

PegCount* AddressSpaceSelectorModule::get_counts() const
{ return (PegCount*)&address_space_select_stats; }

