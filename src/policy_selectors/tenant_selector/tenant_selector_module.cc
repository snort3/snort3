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
// selector_module.cc author Ron Dempster <rdempste@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tenant_selector_module.h"

#include "framework/module.h"
#include "log/messages.h"
#include "main/shell.h"
#include "main/snort_config.h"
#include "policy_selectors/parse_int_set.h"

using namespace snort;
using namespace std;

THREAD_LOCAL PolicySelectStats tenant_select_stats;

static const PegInfo select_pegs[] =
{
    { CountType::SUM, "packets", "packets evaluated" },
    { CountType::SUM, "no_match", "selection evaluations that had no matches" },
    { CountType::END, nullptr, nullptr }
};

//-------------------------------------------------------------------------
// selector module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "tenants", Parameter::PT_STRING, nullptr, nullptr,
      "list of tenants to match" },

    { "file", Parameter::PT_STRING, nullptr, nullptr,
      "use configuration in given file" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

TenantSelectorModule::TenantSelectorModule()
    : Module(TENANT_SELECT_NAME, TENANT_SELECT_HELP, s_params, true)
{ }

TenantSelectorModule::~TenantSelectorModule()
{
    policy_selections.clear();
    selection.clear();
}

ProfileStats* TenantSelectorModule::get_profile() const
{ return &tenant_select_perf_stats; }

void TenantSelectorModule::add_policy_file(const char* name)
{ policy_filename = name; }

bool TenantSelectorModule::begin(const char* fqn, int idx, SnortConfig*)
{
    if ( idx && !strcmp(fqn, TENANT_SELECT_NAME) )
    {
        selection.clear();
        policy_filename.clear();
    }

    return true;
}

bool TenantSelectorModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("tenants") )
    {
        if (!parse_int_set<uint32_t>(v, selection.tenants))
            return false;
    }

    // use
    else if ( v.is("file") )
        add_policy_file(v.get_string());

    return true;
}

bool TenantSelectorModule::end(const char* fqn, int idx, SnortConfig* sc)
{
    if ( !strcmp(fqn, TENANT_SELECT_NAME) && idx )
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

void TenantSelectorModule::commit_policy_selection()
{ policy_selections.emplace_back(selection); }

vector<TenantSelection>& TenantSelectorModule::get_policy_selections()
{ return policy_selections; }

const PegInfo* TenantSelectorModule::get_pegs() const
{ return select_pegs; }

PegCount* TenantSelectorModule::get_counts() const
{ return (PegCount*)&tenant_select_stats; }

