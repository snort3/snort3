//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

class PlugInterface;

struct GlobalPig;
struct InspectorVector;
struct ServicePig;
struct TrafficPig;

namespace snort
{
struct Packet;
struct SnortConfig;

//-------------------------------------------------------------------------

class InspectorManager
{
public:
    static PlugInterface* get_interface(const InspectApi*);

    static void clear();
    static void new_map();
    static void abort_map();
    static void update_map();
    static void revert_map();
    static void restore_map();
    static void prepare_map();
    static void reconcile_map(SnortConfig*);

    static InspectorVector* get_map();
    static void set_map(InspectorVector*);

    static void tear_down(SnortConfig*);
    static void cleanup();

    static void dump_buffers();
    static void release_plugins();

#ifdef SHELL
    static void dump_inspector_map();
#endif

    static std::vector<const InspectApi*> get_apis();
    static const char* get_inspector_type(const char* name);

    static TrafficPig* create_traffic_group();
    static void delete_group(TrafficPig*);

    static ServicePig* create_service_group();
    static void delete_group(ServicePig*);

    static GlobalPig* create_global_group();
    static void delete_group(GlobalPig*);

    static InspectSsnFunc get_session(const char* name, uint16_t proto);

    static bool configure(SnortConfig*);
    static void prepare_inspectors(SnortConfig*);
    static void print_config(SnortConfig*);

    static void thread_init();
    static void thread_term();
    static void thread_term_removed();
    static void thread_reinit(const SnortConfig*);

    static void execute(Packet*);
    static void probe(Packet*);
    static void probe_first(Packet*);

    static void clear(Packet*);
    static void empty_trash();

    static Inspector* get_binder();

    static Inspector* acquire_file_inspector();
    static Inspector* get_file_inspector(const SnortConfig* = nullptr);

    static Inspector* get_service_inspector(const SnortProtocolId);
    static Inspector* get_service_inspector(const char*);

    // uses the currently active policies only
    static Inspector* get_inspector(const char* key, Module::Usage);

    // only valid during swap (eg inspector dtor gets new instance)
    static Inspector* get_new_inspector(const char* key);

    // only valid during configure
    static Inspector* get_old_inspector(const char* key, Module::Usage);

    static void release(Inspector*);

#ifdef REG_TEST
    static void instantiate(const InspectApi*, Module*, SnortConfig*, const char*);
#endif

private:
    static void bumble(Packet*);

    template<bool T> static void full_inspection(Packet*);
    template<bool T> static void internal_execute(Packet*);
};
}
#endif

