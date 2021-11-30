//--------------------------------------------------------------------------
// Copyright (C) 2021-2021 Cisco and/or its affiliates. All rights reserved.
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
// address_space_selector.cc author Ron Dempster <rdempste@cisco.com>

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

#include "address_space_selector_module.h"
#include "address_space_selection.h"

using namespace snort;

THREAD_LOCAL ProfileStats address_space_selectPerfStats;

//-------------------------------------------------------------------------
// helpers
//-------------------------------------------------------------------------

static std::string to_string(const std::vector<uint32_t>& as)
{
    std::string when;

    if (!as.empty())
    {
        auto addr_spaces = int_set_to_string<uint32_t>(as);
        when += "addr_spaces = " + addr_spaces;
    }

    return when;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class AddressSpaceSelector : public PolicySelector
{
public:
    AddressSpaceSelector(const PolicySelectorApi*, std::vector<AddressSpaceSelection>&);
    ~AddressSpaceSelector() override;

    void show() const override;

    bool select_default_policies(const _daq_pkt_hdr*, const SnortConfig*) override;

protected:
    std::vector<AddressSpaceSelection> policy_selections;
    std::unordered_map<uint32_t, snort::PolicySelectUse*> policy_map;
};

AddressSpaceSelector::AddressSpaceSelector(const PolicySelectorApi* api_in,
    std::vector<AddressSpaceSelection>& psv) : PolicySelector(api_in)
{
    policy_selections = std::move(psv);
    for (auto i = policy_selections.rbegin(); i != policy_selections.rend(); ++i)
    {
        std::sort((*i).addr_spaces.begin(), (*i).addr_spaces.end());
        for(auto j = (*i).addr_spaces.begin(); j != (*i).addr_spaces.end(); ++j)
            policy_map[*j] = &(*i).use;
    }
}

AddressSpaceSelector::~AddressSpaceSelector()
{
    for (AddressSpaceSelection& s : policy_selections)
        s.clear();
}

void AddressSpaceSelector::show() const
{
    bool log_header = true;
    for (const AddressSpaceSelection& s : policy_selections)
    {
        if (log_header)
        {
            ConfigLogger::log_option("policy_selections");
            log_header = false;
        }

        std::string select;
        std::string when = to_string(s.addr_spaces);
        if (when.empty())
            select = "{ " + s.use.stringify() + " }";
        else
            select = "{ " + when + ", " + s.use.stringify() + " }";
        ConfigLogger::log_list("", select.c_str(), "   ");
    }
}

bool AddressSpaceSelector::select_default_policies(const _daq_pkt_hdr* pkthdr, const SnortConfig* sc)
{
    Profile profile(address_space_selectPerfStats);

    address_space_select_stats.packets++;

    auto i = policy_map.find(static_cast<uint32_t>(pkthdr->address_space_id));
    if (i != policy_map.end())
    {
        auto use = (*i).second;
        set_network_policy(sc, use->network_index);
        set_inspection_policy(sc, use->inspection_index);
        set_ips_policy(sc, use->ips_index);
        return true;
    }
    address_space_select_stats.no_match++;
    return false;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new AddressSpaceSelectorModule; }

static void mod_dtor(Module* m)
{ delete m; }

static PolicySelector* address_space_select_ctor(Module*);
static void address_space_select_dtor(PolicySelector*);

static const PolicySelectorApi select_api =
{
    {
        PT_POLICY_SELECTOR,
        sizeof(PolicySelectorApi),
        POLICY_SELECTOR_API_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        ADDRESS_SPACE_SELECT_NAME,
        ADDRESS_SPACE_SELECT_HELP,
        mod_ctor,
        mod_dtor
    },
    address_space_select_ctor,
    address_space_select_dtor,
};

const BaseApi* ps_address_space_selector = &select_api.base;

static PolicySelector* address_space_select_ctor(Module* m)
{
    AddressSpaceSelectorModule* mod = static_cast<AddressSpaceSelectorModule*>(m);
    std::vector<AddressSpaceSelection>& psv = mod->get_policy_selections();
    return new AddressSpaceSelector(&select_api, psv);
}

static void address_space_select_dtor(PolicySelector* p)
{ delete p; }

