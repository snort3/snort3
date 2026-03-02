//--------------------------------------------------------------------------
// Copyright (C) 2025-2025 Cisco and/or its affiliates. All rights reserved.
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
// policy_switcher.h author Russ Combs <rucombs@cisco.com>

#ifndef POLICY_SWITCHER_H
#define POLICY_SWITCHER_H

// use this when processing flows without packets (eg when pruning)

#include "main/policy.h"

namespace snort
{
    class Flow;
};

class PolicySwitcher
{
public:
    PolicySwitcher(snort::Flow*);
    ~PolicySwitcher();

private:
    NetworkPolicy* con;
    InspectionPolicy* nap;
    IpsPolicy* ips;
};

#endif

