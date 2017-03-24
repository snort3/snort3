//--------------------------------------------------------------------------
// Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
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

struct SnortConfig;
struct IpsApi;

//-------------------------------------------------------------------------

#ifdef PIGLET
struct IpsOptionWrapper
{
    IpsOptionWrapper(const IpsApi* a, IpsOption* p) :
        api { a }, instance { p } { }

    ~IpsOptionWrapper()
    {
        if ( api && instance && api->dtor )
            api->dtor(instance);
    }

    const IpsApi* api;
    IpsOption* instance;
};
#endif

class IpsManager
{
public:
    static void add_plugin(const IpsApi*);
    static void dump_plugins();
    static void release_plugins();

    static void instantiate(const IpsApi*, Module*, SnortConfig*);

    static bool get_option(
        SnortConfig*, struct OptTreeNode*, int proto,
        const char* keyword, char* args, RuleOptType&);

    static bool option_begin(SnortConfig*, const char* key, int proto);
    static bool option_set(
        SnortConfig*, const char* key, const char* opt, const char* val);
    static bool option_end(
        SnortConfig*, OptTreeNode*, int proto, const char* key, RuleOptType&);

    static void delete_option(class IpsOption*);
    static const char* get_option_keyword();

    static void global_init(SnortConfig*);
    static void global_term(SnortConfig*);

    static void reset_options();
    static void setup_options();
    static void clear_options();
    static bool verify(SnortConfig*);

#ifdef PIGLET
    static IpsOptionWrapper* instantiate(const char*, Module*, struct OptTreeNode*);
#endif
};

#endif

