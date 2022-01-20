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
// policy_selector.h author Ron Dempster <rdempste@cisco.com>

#ifndef POLICY_SELECTOR_H
#define POLICY_SELECTOR_H

// Policy selectors provide a method to select the network policy and default inspection
// and IPS policies for a given packet

#include <string>

#include "framework/base_api.h"
#include "framework/counts.h"
#include "main/snort_types.h"

struct _daq_pkt_hdr;

namespace snort
{
#define POLICY_SELECTOR_API_VERSION ((BASE_API_VERSION << 16) | 0)

struct Packet;
class PolicySelector;
struct PolicySelectorApi;
struct SnortConfig;

struct PolicySelectStats
{
    PegCount packets;
    PegCount no_match;
};

struct PolicySelectUse
{
    std::string stringify() const
    { return "file = " + name; }

    std::string name;
    unsigned network_index;
    unsigned inspection_index;
    unsigned ips_index;
};

typedef PolicySelector* (*SelectorNewFunc)(Module*);
typedef void (*SelectorDeleteFunc)(PolicySelector*);

struct PolicySelectorApi
{
    BaseApi base;
    SelectorNewFunc ctor;
    SelectorDeleteFunc dtor;
};

class SO_PUBLIC PolicySelector
{
public:
    PolicySelector() = delete;
    PolicySelector(const PolicySelector&) = delete;
    virtual ~PolicySelector() = default;

    static void free_policy_selector(PolicySelector* ps)
    {
        if (ps)
            ps->get_api()->dtor(ps);
    }
    const PolicySelectorApi* get_api() const
    { return api; }
    virtual bool select_default_policies(const _daq_pkt_hdr*, const SnortConfig*) = 0;
    virtual void show() const = 0;

protected:
    explicit PolicySelector(const PolicySelectorApi* api) : api(api)
    { }
    const PolicySelectorApi* api;
};
}
#endif

