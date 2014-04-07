/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
// ips_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef IPS_MANAGER_H
#define IPS_MANAGER_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "snort_types.h"
#include "detection/detection_options.h"
#include "framework/base_api.h"
#include "framework/so_rule.h"

struct SnortConfig;
struct IpsApi;
struct SoApi;

//-------------------------------------------------------------------------

class IpsManager
{
public:
    static void add_plugin(const IpsApi*);
    static void add_plugin(const SoApi*);
    static void dump_plugins();
    static void release_plugins();

    static void instantiate(const IpsApi*, Module*, SnortConfig*);
    static void instantiate(const SoApi*);

    static bool get_option(
            SnortConfig*, struct OptTreeNode*, int proto,
        const char* keyword, char* args, int&);
    static void delete_option(class IpsOption*);
    static const char* get_option_keyword();

    // soid is arg to soid option, so is arg to so option
    static const char* get_so_options(const char* soid);
    static so_eval_f get_so_eval(const char* soid, const char* so, void** data);
    static void delete_so_data(const char* soid, void*);

    static void global_init(SnortConfig*);
    static void global_term(SnortConfig*);

    static void setup_options();
    static void clear_options();
    static bool verify();

    static void dump_rule_stubs(const char*);
};

#endif

