//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

class IpsManager
{
public:
    static void add_plugin(const snort::IpsApi*);
    static void dump_plugins();
    static void release_plugins();
    static void instantiate(const snort::IpsApi*, snort::Module*, snort::SnortConfig*);

    static bool option_begin(snort::SnortConfig*, const char* key, SnortProtocolId);
    static bool option_set(
        snort::SnortConfig*, const char* key, const char* opt, const char* val);
    static snort::IpsOption* option_end(
        snort::SnortConfig*, OptTreeNode*, SnortProtocolId, const char* key, snort::RuleOptType&);

    static void delete_option(snort::IpsOption*);
    static const char* get_option_keyword();

    SO_PUBLIC static const snort::IpsApi* get_option_api(const char* keyword);

    static void global_init(const snort::SnortConfig*);
    static void global_term(const snort::SnortConfig*);

    static void reset_options();
    static void setup_options(const snort::SnortConfig*);
    static void clear_options(const snort::SnortConfig*);

    static bool verify(snort::SnortConfig*);
};

#endif

