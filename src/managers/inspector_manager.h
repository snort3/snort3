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
// inspector_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef INSPECTOR_MANAGER_H
#define INSPECTOR_MANAGER_H

// Factory for Inspectors.
// Also provides packet evaluation.

#include <map>

#include "framework/inspector.h"
#include "framework/module.h"

class Binder;
class SingleInstanceInspectorPolicy;
struct InspectorList;
struct InspectionPolicy;
struct NetworkPolicy;
struct PHInstance;
struct GlobalInspectorPolicy;

namespace snort
{
struct Packet;
struct SnortConfig;

//-------------------------------------------------------------------------

class InspectorManager
{
public:
    static void add_plugin(const InspectApi* api);
    static void dump_plugins();
    static void dump_buffers();
    static void release_plugins();

    static void global_init();

    static std::vector<const InspectApi*> get_apis();
    static const char* get_inspector_type(const char* name);

    static void new_policy(NetworkPolicy*, NetworkPolicy*);
    static void delete_policy(NetworkPolicy*, bool cloned);

    static void new_policy(InspectionPolicy*, InspectionPolicy*);
    static void delete_policy(InspectionPolicy*, bool cloned);

    static void update_policy(SnortConfig* sc);

    static void new_config(SnortConfig*);
    static void delete_config(SnortConfig*);

    static void instantiate(
        const InspectApi*, Module*, SnortConfig*, const char* name = nullptr);

    static bool delete_inspector(SnortConfig*, const char* iname);
    static void free_inspector(Inspector*);
    static SingleInstanceInspectorPolicy* create_single_instance_inspector_policy();
    static void destroy_single_instance_inspector(SingleInstanceInspectorPolicy*);
    static GlobalInspectorPolicy* create_global_inspector_policy(GlobalInspectorPolicy* = nullptr);
    static void destroy_global_inspector_policy(GlobalInspectorPolicy*, bool cloned);
    static InspectSsnFunc get_session(uint16_t proto);

    SO_PUBLIC static Inspector* get_file_inspector(const SnortConfig* = nullptr);
    SO_PUBLIC static Inspector* get_inspector(
        const char* key, bool dflt_only = false, const SnortConfig* = nullptr);
    SO_PUBLIC static Inspector* get_inspector(const char* key, Module::Usage, InspectorType,
        const SnortConfig* = nullptr);

    static Inspector* get_service_inspector_by_service(const char*);
    static Inspector* get_service_inspector_by_id(const SnortProtocolId);

    SO_PUBLIC static Binder* get_binder();

    SO_PUBLIC static Inspector* acquire_file_inspector();
    SO_PUBLIC static void release(Inspector*);

    static bool configure(SnortConfig*, bool cloned = false);
    static void prepare_inspectors(SnortConfig*);
    static void prepare_controls(SnortConfig*);
    static std::string generate_inspector_label(const PHInstance*);
    static void print_config(SnortConfig*);

    static void thread_init(const SnortConfig*);
    static void thread_reinit(const SnortConfig*);
    static void thread_stop_removed(const SnortConfig*);

    static void thread_stop(const SnortConfig*);
    static void thread_term();

    static void execute(Packet*);
    static void probe(Packet*);

    static void clear(Packet*);
    static void empty_trash();
    static void reconcile_inspectors(const SnortConfig*, SnortConfig*, bool cloned = false);
    static void clear_removed_inspectors(SnortConfig*);

private:
    static void bumble(Packet*);
    template<bool T> static void full_inspection(Packet*);
    template<bool T> static void internal_execute(Packet*);
    static void sort_inspector_list(const InspectorList* il,
        std::map<const std::string, const PHInstance*>& sorted_ilist);
};
}
#endif

