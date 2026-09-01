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

#include <cstdarg>
#include <cstdio>
#include <string>

#include "detection/detection_engine.h"
#include "flow/expect_flow.h"
#include "flow/flow.h"
#include "flow/session.h"
#include "main/policy.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "managers/inspector_manager.h"
#include "managers/plugin_manager.h"
#include "framework/reload_survivor_subscriptions.h"
#include "framework/reload_survivor_subscriptions_impl.h"
#include "network_inspectors/binder/bind_module.h"
#include "profiler/rule_profiler_defs.h"
#include "profiler/time_profiler_defs.h"
#include "pub_sub/intrinsic_event_ids.h"
#include "search_engines/search_tool.h"
#include "stream/stream.h"
#include "stream/stream_splitter.h"
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

// captures the rendered text so tests can assert on message content, not
// just that a warning fired
static std::string last_warning_message;

void WarningMessage(const char* format, ...)
{
    char buf[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    last_warning_message = buf;
}

DataBus::DataBus() { }
DataBus::~DataBus() { }

using TestDataBusPublishHook = void (*)(unsigned, Packet*);
static TestDataBusPublishHook test_data_bus_publish_hook = nullptr;

void DataBus::publish(unsigned, unsigned event_id, Packet* packet, Flow*)
{
    if ( test_data_bus_publish_hook )
        test_data_bus_publish_hook(event_id, packet);
}
unsigned DataBus::get_id(const PubKey&) { return 0; }

// test-only recorder: ReloadSurvivorSubscriptions ctor stashes (np, ip, survivor);
// list_survivors() returns the seeded vector so tests can drive the resweep pass
struct RssCapture
{
    unsigned ctor_calls = 0;
    unsigned end_reconcile_calls = 0;
    NetworkPolicy* last_np = nullptr;
    InspectionPolicy* last_ip = nullptr;
    Inspector* last_survivor = nullptr;

    std::vector<RssSurvivorView> survivors;

    // release() defers (returns false) for the first release_defer_count calls
    unsigned release_defer_count = 0;
    unsigned release_calls = 0;

    // await_quiescent() defers (returns false) for the first
    // await_quiescent_defer_count calls
    unsigned await_quiescent_defer_count = 0;
    unsigned await_quiescent_calls = 0;

    void reset()
    {
        ctor_calls = 0;
        end_reconcile_calls = 0;
        last_np = nullptr;
        last_ip = nullptr;
        last_survivor = nullptr;
        survivors.clear();
        release_defer_count = 0;
        release_calls = 0;
        await_quiescent_defer_count = 0;
        await_quiescent_calls = 0;
    }
};
static RssCapture rss_capture;

ReloadSurvivorSubscriptions::ReloadSurvivorSubscriptions(
    NetworkPolicy& np_, InspectionPolicy& ip_, Inspector& survivor_)
    : np(np_), ip(ip_), survivor(survivor_)
{
    ++rss_capture.ctor_calls;
    rss_capture.last_np = &np_;
    rss_capture.last_ip = &ip_;
    rss_capture.last_survivor = &survivor_;
}

bool rss_release(Inspector&)
{
    ++rss_capture.release_calls;
    if ( rss_capture.release_calls <= rss_capture.release_defer_count )
        return false;
    return true;
}

bool rss_await_quiescent(Inspector&)
{
    ++rss_capture.await_quiescent_calls;
    if ( rss_capture.await_quiescent_calls <= rss_capture.await_quiescent_defer_count )
        return false;
    return true;
}

void rss_on_bus_destroyed(const DataBus*) { }
void rss_end_reconcile(Inspector&)
{ ++rss_capture.end_reconcile_calls; }

std::vector<RssSurvivorView>
rss_list_survivors()
{
    std::vector<RssSurvivorView> out = rss_capture.survivors;
    return out;
}

RssStats rss_stats;

void Flow::set_service(Packet* packet, const char* new_service)
{
    service = new_service;
    DataBus::publish(intrinsic_pub_id, IntrinsicEventIds::FLOW_SERVICE_CHANGE, packet);
}

Flow::Flow() { }
Flow::~Flow() = default;
void FlowStash::reset() { }
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

void Flow::pin_survivor_flow_data(Inspector&) { }

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

Packet::Packet(bool) { }
Packet::~Packet() = default;

const StreamBuffer StreamSplitter::reassemble(
    Flow*, unsigned, unsigned, const uint8_t*, unsigned, uint32_t, unsigned&)
{ return { nullptr, 0 }; }

unsigned StreamSplitter::max(Flow*)
{ return 0; }

uint16_t StreamSplitter::get_flush_bucket_size()
{ return 0; }

AtomSplitter::AtomSplitter(bool to_server, uint16_t size) : StreamSplitter(to_server),
    base(size), min(size), segs(0)
{ }

StreamSplitter::Status AtomSplitter::scan(
    Packet*, const uint8_t*, uint32_t, uint32_t, uint32_t*)
{ return SEARCH; }

bool AtomSplitter::restart()
{ return true; }

void Stream::set_splitter(Flow* flow, bool to_server, StreamSplitter* splitter)
{ flow->session->set_splitter(to_server, splitter); }

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
