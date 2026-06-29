//--------------------------------------------------------------------------
// Copyright (C) 2020-2026 Cisco and/or its affiliates. All rights reserved.
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
// stubs.h author Ron Dempster <rdempste@cisco.com>

#ifndef GET_INSPECTOR_STUBS_H
#define GET_INSPECTOR_STUBS_H

#include "detection/detection_engine.h"
#include "flow/expect_flow.h"
#include "flow/flow.h"
#include "main/policy.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "managers/inspector_manager.h"
#include "managers/plugin_manager.h"
#include "network_inspectors/binder/bind_module.h"
#include "profiler/rule_profiler_defs.h"
#include "profiler/time_profiler_defs.h"
#include "search_engines/search_tool.h"
#include "trace/trace.h"
#include "trace/trace_api.h"

THREAD_LOCAL const snort::Trace* snort_trace = nullptr;

std::shared_ptr<PolicyTuple> PolicyMap::get_policies(Shell*) { return nullptr; }
void InspectionPolicy::configure() { }
void BinderModule::add(const char*, const char*) { }
void BinderModule::add(unsigned, const char*) { }

void update_buffer_map(const char**, const char*) { }

PluginPtr PluginManager::get_plugin(const char*) { return nullptr; }
snort::Module* PluginManager::get_module(const char*) { return nullptr; }

namespace snort
{
[[noreturn]] void FatalError(const char*,...) { exit(-1); }
void LogMessage(const char*, ...) { }
void LogLabel(const char*, FILE*) { }
void ParseError(const char*, ...) { }
void WarningMessage(const char*, ...) { }

DataBus::DataBus() { }
DataBus::~DataBus() { }

void DataBus::publish(unsigned, unsigned, Packet*, Flow*) { }
unsigned DataBus::get_id(const PubKey&) { return 0; }

void Flow::set_service(Packet*, const char* new_service)
{ service = new_service; }

Flow::~Flow() = default;
FlowDataStore::~FlowDataStore() = default;

void Flow::release_gadget()
{
    Inspector* old_gadget = gadget;

    if ( !old_gadget )
        return;

    gadget = nullptr;
    old_gadget->rem_ref();
    InspectorManager::thread_drain_pending_tterm_if_pending(old_gadget);
}

void DetectionEngine::disable_content(Packet*) { }

Inspector::Inspector()
{
    const unsigned max = 1 + ThreadConfig::get_instance_max();
    ref_count = new std::atomic_uint[max];

    for ( unsigned slot = 0; slot < max; ++slot )
        ref_count[slot] = 0;
}

Inspector::~Inspector()
{ delete[] ref_count; }
bool Inspector::get_buf(const char*, Packet*, InspectionBuffer&) { return false; }
StreamSplitter* Inspector::get_splitter(bool) { return nullptr; }
bool Inspector::is_inactive()
{
    for ( unsigned slot = 0; slot < 1 + ThreadConfig::get_instance_max(); ++slot )
        if ( ref_count[slot] )
            return false;

    return true;
}
bool Inspector::likes(Packet*) { return false; }
void Inspector::add_global_ref() { ++ref_count[0]; }
void Inspector::add_ref() { ++ref_count[1 + get_instance_id()]; }
void Inspector::rem_ref() { --ref_count[1 + get_instance_id()]; }
void Inspector::rem_global_ref() { --ref_count[0]; }
void Inspector::allocate_thread_storage() { }
void Inspector::copy_thread_storage(snort::Inspector*) { }
const char* InspectApi::get_type(InspectorType) { return ""; }

unsigned ThreadConfig::get_instance_max() { return 1; }
SnortProtocolId ProtocolReference::find(const char*) const { return UNKNOWN_PROTOCOL_ID; }
SnortProtocolId ProtocolReference::add(const char*) { return UNKNOWN_PROTOCOL_ID; }
uint8_t TraceApi::get_constraints_generation() { return 0; }
void TraceApi::filter(const Packet&) { }

void ExpectFlow::handle_expected_flows(const Packet*) { }

NetworkPolicy* get_default_network_policy(const SnortConfig*) { return nullptr; }
void set_ips_policy(IpsPolicy*) { }
unsigned get_instance_id() { return 0; }
void trace_vprintf(const char*, TraceLevel, const char*, const Packet*, const char*, va_list) { }

NetworkPolicy* get_network_parse_policy() { return nullptr; }

Module::Module(const char* name, const char*) : name(name), help(nullptr), params(nullptr), list(false) { }
PegCount Module::get_global_count(const char*) const { return 0; }
void Module::sum_stats(bool) { }
void Module::init_stats(bool) { }
void Module::main_accumulate_stats() { }
void Module::show_interval_stats(std::vector<unsigned>&, FILE*) { }
void Module::show_stats() { }
void Module::reset_stats() { }
}
unsigned PluginManager::for_each(PlugType, PluginManager::BaseFunc, void*) { return 0; }
unsigned PluginManager::for_each(PlugType, PluginManager::PlugFunc, void*) { return 0; }
const snort::BaseApi* PluginManager::get_api(char const*) { return nullptr; }

#endif

