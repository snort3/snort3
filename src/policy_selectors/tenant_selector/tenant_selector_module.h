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
// tenant_selector_module.h author Ron Dempster <rdempste@cisco.com>

#ifndef TENANT_SELECTOR_MODULE_H
#define TENANT_SELECTOR_MODULE_H

// tenant selector management interface

#include <string>
#include <vector>

#include "framework/module.h"
#include "tenant_selection.h"

#define TENANT_SELECT_NAME "tenant_selector"
#define TENANT_SELECT_HELP "configure traffic processing based on tenants"

extern THREAD_LOCAL snort::PolicySelectStats tenant_select_stats;
extern THREAD_LOCAL snort::ProfileStats tenant_select_perf_stats;

class TenantSelectorModule : public snort::Module
{
public:
    TenantSelectorModule();
    ~TenantSelectorModule() override;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*) override;
    bool end(const char*, int, snort::SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    snort::ProfileStats* get_profile() const override;

    std::vector<TenantSelection>& get_policy_selections();

    Usage get_usage() const override
    { return GLOBAL; }

private:
    TenantSelection selection;
    std::vector<TenantSelection> policy_selections;
    std::string policy_filename;

    void add_policy_file(const char* name);
    void commit_policy_selection();
};

#endif

