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
// so_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef SO_MANAGER_H
#define SO_MANAGER_H

// Factory for shared object rules.
// Runtime is same as for text rules.

#include "framework/so_rule.h"

namespace snort
{
struct SnortConfig;
}
struct SoApi;

//-------------------------------------------------------------------------

class SoManager
{
public:
    static void add_plugin(const SoApi*);
    static void dump_plugins();
    static void release_plugins();

    static void instantiate(const SoApi*);

    // soid is arg to soid option, so is arg to so option
    static const char* get_so_options(const char* soid);
    static SoEvalFunc get_so_eval(const char* soid, const char* so, void** data);
    static void delete_so_data(const char* soid, void*);

    static void rule_to_hex(const char* file);
    static void rule_to_text(const char* file);
    static void dump_rule_stubs(const char*);
};

#endif

