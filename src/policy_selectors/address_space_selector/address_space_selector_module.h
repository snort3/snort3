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
// address_space_selector_module.h author Ron Dempster <rdempste@cisco.com>

#ifndef ADDRESS_SPACE_SELECTOR_MODULE_H
#define ADDRESS_SPACE_SELECTOR_MODULE_H

// address space selector management interface

#include "framework/module.h"
#include "framework/policy_selector.h"
#include "address_space_selection.h"

#define ADDRESS_SPACE_SELECT_NAME "address_space_selector"
#define ADDRESS_SPACE_SELECT_HELP "configure traffic processing based on address space"

extern THREAD_LOCAL snort::PolicySelectStats address_space_select_stats;
extern THREAD_LOCAL snort::ProfileStats address_space_selectPerfStats;

class AddressSpaceSelectorModule : public snort::Module
{
public:
    AddressSpaceSelectorModule();
    ~AddressSpaceSelectorModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    std::vector<AddressSpaceSelection>& get_policy_selections();

    Usage get_usage() const override
    { return GLOBAL; }

private:
    AddressSpaceSelection selection;
    std::vector<AddressSpaceSelection> policy_selections;
    std::string policy_filename;

    void add_policy_file(const char* name);
    void commit_policy_selection();
};

#endif

