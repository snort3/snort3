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
// policy_switcher.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow/flow.h"
#include "flow/flow_key.h"
#include "main/snort_config.h"

#include "policy_switcher.h"

using namespace snort;

PolicySwitcher::PolicySwitcher(Flow* flow)
{
    con = get_network_policy();
    nap = get_inspection_policy();
    ips = get_ips_policy();

    if ( flow->reload_id == SnortConfig::get_reload_id() )
    {
        set_network_policy(flow->network_policy_id);
        set_inspection_policy(flow->inspection_policy_id);
        set_ips_policy(SnortConfig::get_conf(), flow->ips_policy_id);
    }
    else
    {
        _daq_pkt_hdr pkthdr = {};
        pkthdr.address_space_id = flow->key ? flow->key->addressSpaceId : 0;
#ifndef DISABLE_TENANT_ID
        pkthdr.tenant_id = flow->key ? flow->key->tenant_id : 0;
#else
        pkthdr.tenant_id = 0;
#endif
        select_default_policy(pkthdr, SnortConfig::get_conf());
        flow->reload_id = SnortConfig::get_reload_id();
    }
}

PolicySwitcher::~PolicySwitcher()
{
    set_network_policy(con);
    set_inspection_policy(nap);
    set_ips_policy(ips);
}

