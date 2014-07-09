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
// inspector_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef INSPECTOR_MANAGER_H
#define INSPECTOR_MANAGER_H

#include "snort_types.h"
#include "framework/base_api.h"
#include "framework/inspector.h"

struct Packet;
struct FrameworkPolicy;
struct SnortConfig;
struct InspectionPolicy;

//-------------------------------------------------------------------------

class InspectorManager
{
public:
    static void add_plugin(const InspectApi* api);
    static void dump_plugins(void);
    static void dump_buffers(void);
    static void release_plugins(void);

    static void new_policy(InspectionPolicy*);
    static void delete_policy(InspectionPolicy*);

    static void new_config(SnortConfig*);
    static void delete_config(SnortConfig*);

    static void dump_stats(SnortConfig*);
    static void accumulate(SnortConfig*);
    static void reset_stats(SnortConfig*);

    static void instantiate(const InspectApi*, Module*, SnortConfig*);
    static Inspector* get_inspector(const char* key);
    static void free_inspector(Inspector*);
    static InspectSsnFunc get_session(const char* key);

    static bool configure(SnortConfig*);
    static void print_config(SnortConfig*);

    static void thread_init(SnortConfig*);
    static void thread_term(SnortConfig*);

    static void release_policy(FrameworkPolicy*);
    static void dispatch_meta(FrameworkPolicy*, int type, const uint8_t* data);

    static void execute(Packet*);
    static void bumble(Packet*);
    static void empty_trash();
};

#endif

