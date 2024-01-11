//--------------------------------------------------------------------------
// Copyright (C) 2021-2024 Cisco and/or its affiliates. All rights reserved.
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
// selector.cc author Ron Dempster <rdempste@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <algorithm>
#include <unordered_map>
#include <vector>

#include "detection/ips_context.h"
#include "framework/policy_selector.h"
#include "log/messages.h"
#include "policy_selectors/int_set_to_string.h"
#include "profiler/profiler.h"

#include "tenant_selector_module.h"
#include "tenant_selection.h"

using namespace snort;

THREAD_LOCAL ProfileStats tenant_select_perf_stats;

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

static std::string to_string(const std::vector<uint32_t>& t)
{
    std::string when;

    if (!t.empty())
    {
        auto tenants = int_set_to_string<uint32_t>(t);
        when += "tenants = " + tenants;
    }

    return when;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class TenantSelector : public PolicySelector
{
public:
    TenantSelector(const PolicySelectorApi*, std::vector<TenantSelection>&);
    ~TenantSelector() override;

    void show() const override;

    bool select_default_policies(const _daq_pkt_hdr&, const SnortConfig*) override;
    bool select_default_policies(const _daq_flow_stats&, const SnortConfig*) override;

protected:
    bool select_default_policies(uint32_t key, const SnortConfig*);
    std::vector<TenantSelection> policy_selections;
    std::unordered_map<uint32_t, snort::PolicySelectUse*> policy_map;
};

TenantSelector::TenantSelector(const PolicySelectorApi* api_in, std::vector<TenantSelection>& psv)
    : PolicySelector(api_in), policy_selections(std::move(psv))
{
    for (auto i = policy_selections.rbegin(); i != policy_selections.rend(); ++i)
    {
        std::sort((*i).tenants.begin(), (*i).tenants.end());
        for(auto j = (*i).tenants.begin(); j != (*i).tenants.end(); ++j)
            policy_map[*j] = &(*i).use;
    }
}

TenantSelector::~TenantSelector()
{
    for (TenantSelection& s : policy_selections)
        s.clear();
}

void TenantSelector::show() const
{
    bool log_header = true;
    for (const TenantSelection& s : policy_selections)
    {
        if (log_header)
        {
            ConfigLogger::log_option("policy_selections");
            log_header = false;
        }

        std::string select;
        std::string when = to_string(s.tenants);
        if (when.empty())
            select = "{ " + s.use.stringify() + " }";
        else
            select = "{ " + when + ", " + s.use.stringify() + " }";
        ConfigLogger::log_list("", select.c_str(), "   ");
    }
}

bool TenantSelector::select_default_policies(uint32_t key, const SnortConfig* sc)
{
    // cppcheck-suppress unreadVariable
    Profile profile(tenant_select_perf_stats);

    tenant_select_stats.packets++;

    auto i = policy_map.find(key);
    if (i != policy_map.end())
    {
        auto use = (*i).second;
        set_network_policy(use->network_index);
        set_inspection_policy(use->inspection_index);
        set_ips_policy(sc, use->ips_index);
        return true;
    }
    tenant_select_stats.no_match++;
    return false;
}

bool TenantSelector::select_default_policies(const _daq_pkt_hdr& pkthdr, const SnortConfig* sc)
{ return select_default_policies(static_cast<uint32_t>(pkthdr.tenant_id), sc); }

bool TenantSelector::select_default_policies(const _daq_flow_stats& stats, const SnortConfig* sc)
{ return select_default_policies(static_cast<uint32_t>(stats.tenant_id), sc); }

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new TenantSelectorModule; }

static void mod_dtor(Module* m)
{ delete m; }

static PolicySelector* tenant_select_ctor(Module*);

static void tenant_select_dtor(PolicySelector* p)
{ delete p; }


static const PolicySelectorApi select_api =
{
    {
        PT_POLICY_SELECTOR,
        sizeof(PolicySelectorApi),
        POLICY_SELECTOR_API_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        TENANT_SELECT_NAME,
        TENANT_SELECT_HELP,
        mod_ctor,
        mod_dtor
    },
    tenant_select_ctor,
    tenant_select_dtor,
};

const BaseApi* ps_tenant_selector = &select_api.base;

static PolicySelector* tenant_select_ctor(Module* m)
{
    TenantSelectorModule* mod = static_cast<TenantSelectorModule*>(m);
    std::vector<TenantSelection>& psv = mod->get_policy_selections();
    return new TenantSelector(&select_api, psv);
}

