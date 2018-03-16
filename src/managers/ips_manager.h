//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// ips_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef IPS_MANAGER_H
#define IPS_MANAGER_H

// Factory for IpsOptions.
// Runtime use of IpsOptions is via detection option tree.

#include "detection/detection_options.h"
#include "framework/ips_option.h"
#include "framework/module.h"

namespace snort
{
    struct IpsApi;
    class IpsOption;
    struct SnortConfig;
}

//-------------------------------------------------------------------------

#ifdef PIGLET
struct IpsOptionWrapper
{
    IpsOptionWrapper(const snort::IpsApi* a, snort::IpsOption* p) :
        api { a }, instance { p } { }

    ~IpsOptionWrapper()
    {
        if ( api && instance && api->dtor )
            api->dtor(instance);
    }

    const snort::IpsApi* api;
    snort::IpsOption* instance;
};
#endif

class IpsManager
{
public:
    static void add_plugin(const snort::IpsApi*);
    static void dump_plugins();
    static void release_plugins();

    static void instantiate(const snort::IpsApi*, snort::Module*, snort::SnortConfig*);

    static bool get_option(
        snort::SnortConfig*, struct OptTreeNode*, SnortProtocolId,
        const char* keyword, char* args, snort::RuleOptType&);

    static bool option_begin(snort::SnortConfig*, const char* key, SnortProtocolId);
    static bool option_set(
        snort::SnortConfig*, const char* key, const char* opt, const char* val);
    static bool option_end(
        snort::SnortConfig*, OptTreeNode*, SnortProtocolId, const char* key, snort::RuleOptType&);

    static void delete_option(snort::IpsOption*);
    static const char* get_option_keyword();

    static void global_init(snort::SnortConfig*);
    static void global_term(snort::SnortConfig*);

    static void reset_options();
    static void setup_options();
    static void clear_options();
    static bool verify(snort::SnortConfig*);

#ifdef PIGLET
    static IpsOptionWrapper* instantiate(const char*, snort::Module*, struct OptTreeNode*);
#endif
};

#endif

