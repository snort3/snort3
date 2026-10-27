//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <memory>
#include <string>
#include <vector>

#include "main/policy.h"
#include "managers/plug_interface.h"

#include "packet_io/packet_tracer.h"
#include "stream/base/stream_module.h"
#include "get_inspector_stubs.h"

#include <CppUTest/CommandLineTestRunner.h>
#include "CppUTest/MemoryLeakDetectorNewMacros.h"
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

THREAD_LOCAL BaseStats stream_base_stats = {};

bool PacketTracer::is_active() { return false; }
void PacketTracer::log(const char*, ...) { }

//--------------------------------------------------------------------------
// mocks
//--------------------------------------------------------------------------

NetworkPolicy::NetworkPolicy(PolicyId, PolicyId)
{
    file_policy = nullptr;
    traffic_group = InspectorManager::create_traffic_group();
}

NetworkPolicy::~NetworkPolicy()
{
    for ( auto p : inspection_policy )
        delete p;

    inspection_policy.clear();
    InspectorManager::delete_group(traffic_group);
}

InspectionPolicy* NetworkPolicy::get_user_inspection_policy(uint64_t user_id) const
{
    auto it = user_inspection.find(user_id);
    return it == user_inspection.end() ? nullptr : it->second;
}

InspectionPolicy::InspectionPolicy(PolicyId)
{ service_group = InspectorManager::create_service_group(); }

InspectionPolicy::~InspectionPolicy()
{ InspectorManager::delete_group(service_group); }

static NetworkPolicy* make_network_policy(uint64_t nid, uint64_t uid)
{
    NetworkPolicy* np = new NetworkPolicy(nid, 0);
    np->user_policy_id = uid;

    for ( unsigned i = 1; i < 3; ++i )
    {
        InspectionPolicy* ip = new InspectionPolicy();
        np->inspection_policy.push_back(ip);
        ip->user_policy_id = uid + i;
        np->set_user_inspection(ip);
    }
    return np;
}

PolicyMap::PolicyMap()
{
    empty_ips_policy = nullptr;
    global_group = InspectorManager::create_global_group();

    for ( unsigned i = 1; i < 3; ++i )
    {
        NetworkPolicy* np = make_network_policy(network_policy.size(), i*10);
        network_policy.push_back(np);
        user_network[np->user_policy_id] = np;
    }
}

PolicyMap::~PolicyMap()
{
    InspectorManager::delete_group(global_group);
    for ( auto p : network_policy )
        delete p;
}

NetworkPolicy* PolicyMap::get_user_network(uint64_t user_id) const
{
    auto it = user_network.find(user_id);
    NetworkPolicy* np = (it == user_network.end()) ? nullptr : it->second;
    return np;
}

void clear_buffer_map() { }

// stands in for update_reload_id() on the incoming config
static const unsigned stub_reload_id = 77;

// the active config's id, deliberately different so assertions show which was used
static const unsigned stub_active_reload_id = 42;

SnortConfig::SnortConfig(const char*)
{
    policy_map = new PolicyMap();
    reload_id.store(stub_reload_id, std::memory_order_relaxed);
    mock().setDataObject("snort_config", "const SnortConfig", this);
}

SnortConfig::~SnortConfig()
{
    delete policy_map;
}

const SnortConfig* SnortConfig::get_conf()
{ return (const SnortConfig*)mock().getData("snort_config").getObjectPointer(); }

unsigned SnortConfig::get_reload_id() { return stub_active_reload_id; }

PlugContext* PluginManager::get_context(char const* s)
{ return (PlugContext*)mock().getData(s).getObjectPointer(); }

namespace snort
{
void set_network_policy(NetworkPolicy* np)
{ mock().setDataObject("network_policy", "NetworkPolicy", np); }

NetworkPolicy* get_network_policy()
{ return (NetworkPolicy*)mock().getData("network_policy").getObjectPointer(); }

void set_inspection_policy(InspectionPolicy* ip)
{ mock().setDataObject("inspect_policy", "InspectionPolicy", ip); }

InspectionPolicy* get_inspection_policy()
{ return (InspectionPolicy*)mock().getData("inspect_policy").getObjectPointer(); }
}

//--------------------------------------------------------------------------
// test implementation
//--------------------------------------------------------------------------

struct ReloadCounts
{
    unsigned configure = 0;
    unsigned tear_down = 0;
    unsigned tinit = 0;
    unsigned tterm = 0;
    NetworkPolicy* tterm_np = nullptr;
    unsigned survivor_handler_registrations = 0;
    bool last_shutdown = false;
    std::shared_ptr<bool> inspector_alive = std::make_shared<bool>(false);
    unsigned to_server_splitter_detaches = 0;
    unsigned to_client_splitter_detaches = 0;
    bool splitters_detached_while_alive = true;
    bool splitters_detached_after_gadget_clear = true;
    Flow* observed_flow = nullptr;
};

class InspectorOwnedSplitter : public StreamSplitter
{
public:
    InspectorOwnedSplitter(bool to_server, ReloadCounts* c, unsigned* detaches) :
        StreamSplitter(to_server), counts(c), detach_count(detaches)
    { }

    Status scan(Packet*, const uint8_t*, uint32_t, uint32_t, uint32_t*) override
    { return SEARCH; }

    void go_away() override
    {
        ++*detach_count;
        counts->splitters_detached_while_alive &= *counts->inspector_alive;
        counts->splitters_detached_after_gadget_clear &=
            !counts->observed_flow or !counts->observed_flow->gadget;
    }

private:
    ReloadCounts* counts = nullptr;
    unsigned* detach_count = nullptr;
};

class ReloadModule : public Module
{
public:
    explicit ReloadModule(const char* s) : Module(s, "reload test inspector")
    { }

    Usage get_usage() const override
    { return usage; }

    static Module* ctor() { return nullptr; }
    static void dtor(Module*) { }

    ReloadCounts* reload_counts = nullptr;
    Usage usage = Module::INSPECT;
};

class ReloadInspector : public Inspector
{
public:
    explicit ReloadInspector(ReloadCounts* c) : counts(c), alive(c->inspector_alive),
        to_server_splitter(true, c, &c->to_server_splitter_detaches),
        to_client_splitter(false, c, &c->to_client_splitter_detaches)
    { *alive = true; }

    ~ReloadInspector() override
    { *alive = false; }

    bool configure(SnortConfig*) override
    {
        ++counts->configure;
        return true;
    }

    void tear_down(SnortConfig*, bool shutdown) override
    {
        ++counts->tear_down;
        counts->last_shutdown = shutdown;
    }

    void tinit() override
    { ++counts->tinit; }

    void tterm() override
    {
        ++counts->tterm;
        counts->tterm_np = get_network_policy();
    }

    void register_reload_survivor_handlers(ReloadSurvivorSubscriptions&) override
    { ++counts->survivor_handler_registrations; }

    StreamSplitter* get_splitter(bool to_server) override
    { return to_server ? &to_server_splitter : &to_client_splitter; }

private:
    ReloadCounts* counts = nullptr;
    std::shared_ptr<bool> alive;
    InspectorOwnedSplitter to_server_splitter;
    InspectorOwnedSplitter to_client_splitter;
};

class ReloadSession : public Session
{
public:
    explicit ReloadSession(Flow* flow) : Session(flow)
    { }

    ~ReloadSession() override
    {
        release_splitter(to_server_splitter);
        release_splitter(to_client_splitter);
    }

    void clear() override
    { }

    void set_splitter(bool to_server, StreamSplitter* splitter) override
    {
        StreamSplitter*& current = to_server ? to_server_splitter : to_client_splitter;

        release_splitter(current);
        current = splitter;
    }

    StreamSplitter* get_splitter(bool to_server) override
    { return to_server ? to_server_splitter : to_client_splitter; }

private:
    static void release_splitter(StreamSplitter*& splitter)
    {
        if ( splitter )
            splitter->go_away();

        splitter = nullptr;
    }

    StreamSplitter* to_server_splitter = nullptr;
    StreamSplitter* to_client_splitter = nullptr;
};

struct ServiceChangeTestContext
{
    Flow* flow = nullptr;
    ReloadSession* session = nullptr;
    Inspector* stale_inspector = nullptr;
    Inspector* replacement_inspector = nullptr;
    ReloadCounts* stale_counts = nullptr;
    unsigned callbacks = 0;
    StreamSplitter* stale_to_server_splitter = nullptr;
    StreamSplitter* stale_to_client_splitter = nullptr;
    StreamSplitter* fallback_to_server_splitter = nullptr;
    StreamSplitter* fallback_to_client_splitter = nullptr;
};

static ServiceChangeTestContext* service_change_test_context = nullptr;
static unsigned get_thread_refs(Inspector*);

static void verify_splitters_safe_during_service_change(unsigned event_id, Packet* packet)
{
    if ( event_id != IntrinsicEventIds::FLOW_SERVICE_CHANGE )
        return;

    ServiceChangeTestContext& context = *service_change_test_context;
    ++context.callbacks;

    POINTERS_EQUAL(context.flow, packet->flow);
    CHECK_FALSE(context.flow->gadget);
    CHECK_FALSE(context.flow->service);
    CHECK(*context.stale_counts->inspector_alive);
    CHECK_EQUAL(2, get_thread_refs(context.stale_inspector));

    if ( context.session )
    {
        CHECK_EQUAL(1, context.stale_counts->to_server_splitter_detaches);
        CHECK_EQUAL(1, context.stale_counts->to_client_splitter_detaches);
        CHECK(context.stale_counts->splitters_detached_while_alive);
        CHECK(context.stale_counts->splitters_detached_after_gadget_clear);

        context.fallback_to_server_splitter = context.session->get_splitter(true);
        context.fallback_to_client_splitter = context.session->get_splitter(false);

        CHECK(context.fallback_to_server_splitter);
        CHECK(context.fallback_to_client_splitter);
        CHECK(context.fallback_to_server_splitter != context.stale_to_server_splitter);
        CHECK(context.fallback_to_client_splitter != context.stale_to_client_splitter);
        CHECK(context.fallback_to_server_splitter->to_server());
        CHECK(context.fallback_to_client_splitter->to_client());
        CHECK(context.fallback_to_server_splitter->restart());
        CHECK(context.fallback_to_client_splitter->restart());
    }
    else
    {
        CHECK_FALSE(context.flow->session);
        CHECK_EQUAL(0, context.stale_counts->to_server_splitter_detaches);
        CHECK_EQUAL(0, context.stale_counts->to_client_splitter_detaches);
    }

    if ( context.replacement_inspector )
    {
        CHECK(context.fallback_to_server_splitter !=
            context.replacement_inspector->get_splitter(true));
        CHECK(context.fallback_to_client_splitter !=
            context.replacement_inspector->get_splitter(false));
        context.session->set_splitter(true, context.replacement_inspector->get_splitter(true));
        context.session->set_splitter(false, context.replacement_inspector->get_splitter(false));
    }
    else
    {
        context.flow->set_state(Flow::FlowState::ALLOW);
        context.flow->disable_inspection();
    }
}

static Inspector* reload_ctor(Module* mod)
{
    auto* reload_module = static_cast<ReloadModule*>(mod);
    return new ReloadInspector(reload_module->reload_counts);
}

static void reload_dtor(Inspector* pin)
{ delete pin; }

static const InspectApi reload_api_template =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        PLUGIN_DEFAULT,
        API_OPTIONS,
        "reload_test",
        "reload test inspector",
        ReloadModule::ctor,
        ReloadModule::dtor,
    },
    IT_SERVICE,
    PROTO_BIT__NONE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    reload_ctor,
    reload_dtor,
    nullptr,
    nullptr
};

static void set_policies(const SnortConfig* sc, uint64_t npid, uint64_t ipid)
{
    NetworkPolicy* np = sc->policy_map->get_user_network(npid);
    CHECK(np);
    set_network_policy(np);

    InspectionPolicy* ip = np->get_user_inspection_policy(ipid);
    CHECK(ip);
    set_inspection_policy(ip);
}

static unsigned thread_ref_slot()
{ return 1 + get_instance_id(); }

static void set_thread_refs(Inspector* pin, unsigned refs)
{ pin->set_ref(thread_ref_slot(), refs); }

static unsigned get_thread_refs(Inspector* pin)
{ return pin->get_ref(thread_ref_slot()); }

struct ReloadPlugin
{
    // usage/type must be set before get_interface(): GLOBAL asserts api != IT_SERVICE
    ReloadPlugin(const char* name, Module::Usage usage = Module::INSPECT,
        InspectorType type = IT_SERVICE) : module(name), api(reload_api_template)
    {
        api.base.name = name;
        api.type = type;
        module.usage = usage;
        plug = InspectorManager::get_interface(&api);
        context = plug->get_context();
        mock().setDataObject(name, "PlugContext", context);
    }

    ~ReloadPlugin()
    {
        delete context;
        delete plug;
    }

    void instantiate(SnortConfig* sc, ReloadCounts& counts, uint64_t npid = 10, uint64_t ipid = 11,
        const char* alias = nullptr)
    {
        module.reload_counts = &counts;
        set_policies(sc, npid, ipid);
        plug->instantiate(&module, sc, alias);
    }

    Inspector* get(const SnortConfig* sc, uint64_t npid = 10, uint64_t ipid = 11, const char* alias = nullptr)
    {
        set_policies(sc, npid, ipid);
        return InspectorManager::get_inspector(alias ? alias : module.get_name(), Module::INSPECT);
    }

    ReloadModule module;
    InspectApi api;
    PlugInterface* plug = nullptr;
    PlugContext* context = nullptr;
};

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

TEST_GROUP(inspector_manager_reload_tests)
{
    std::unique_ptr<SnortConfig> sc;
    std::unique_ptr<ReloadPlugin> reload_plugin;

    // must be a member: a pig dtor can call api->dtor() after a TEST-local one dies
    std::unique_ptr<ReloadPlugin> alt_plugin;

    void setup() override
    {
        InspectorManager::new_map();
        sc.reset(new SnortConfig);
        reload_plugin.reset(new ReloadPlugin("reload_test"));
        snort::rss_capture.reset();
    }

    void teardown() override
    {
        test_data_bus_publish_hook = nullptr;
        service_change_test_context = nullptr;
        sc.reset();
        InspectorManager::empty_trash();
        InspectorManager::cleanup();
        reload_plugin.reset();
        alt_plugin.reset();
    }

    void activate_current_map()
    {
        InspectorManager::prepare_map();
        CHECK(InspectorManager::configure(sc.get()));
        InspectorManager::thread_init();
        InspectorManager::update_map();
    }

    std::unique_ptr<SnortConfig> start_removal_reload()
    {
        InspectorManager::new_map();
        std::unique_ptr<SnortConfig> reload_sc(new SnortConfig);
        InspectorManager::prepare_map();
        InspectorManager::reconcile_map(reload_sc.get());
        return reload_sc;
    }

    std::unique_ptr<SnortConfig> start_reload()
    {
        InspectorManager::new_map();
        return std::unique_ptr<SnortConfig>(new SnortConfig);
    }

    static void reconcile_reload(SnortConfig* reload_sc)
    {
        InspectorManager::prepare_map();
        InspectorManager::reconcile_map(reload_sc);
    }

    void restore_old_map_for_teardown(std::unique_ptr<SnortConfig>& reload_sc)
    {
        reload_sc.reset();
        InspectorManager::revert_map();
        mock().setDataObject("snort_config", "const SnortConfig", sc.get());
    }
};

TEST(inspector_manager_reload_tests, referenced_removed_service_defers_tterm_until_refs_drain)
{
    ReloadCounts old_counts;

    reload_plugin->instantiate(sc.get(), old_counts);
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get());
    CHECK(old_inspector);
    CHECK_EQUAL(1, old_counts.configure);
    CHECK_EQUAL(1, old_counts.tinit);

    set_thread_refs(old_inspector, 1);
    auto reload_sc = start_removal_reload();
    CHECK_EQUAL(1, old_counts.tear_down);
    CHECK_FALSE(old_counts.last_shutdown);

    InspectorManager::thread_term_removed();
    CHECK_EQUAL(0, old_counts.tterm);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    set_thread_refs(old_inspector, 1);
    InspectorManager::thread_drain_pending_tterm();
    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(0, get_thread_refs(old_inspector));

    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, removed_service_without_refs_drains_before_tterm)
{
    ReloadCounts old_counts;

    reload_plugin->instantiate(sc.get(), old_counts);
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get());
    CHECK(old_inspector);

    auto reload_sc = start_removal_reload();
    CHECK_EQUAL(0, old_counts.tterm);
    CHECK_EQUAL(0, snort::rss_capture.await_quiescent_calls);

    // This is the direct, no-flow-ref path in InspectorVector::thread_term.
    // It must use the same drain-before-tterm helper as deferred cleanup.
    InspectorManager::thread_term_removed();

    CHECK_EQUAL(1, snort::rss_capture.await_quiescent_calls);
    CHECK_EQUAL(1, old_counts.tterm);

    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, direct_tterm_defers_when_rss_drain_is_not_ready)
{
    ReloadCounts old_counts;

    reload_plugin->instantiate(sc.get(), old_counts);
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get());
    CHECK(old_inspector);

    auto reload_sc = start_removal_reload();
    snort::rss_capture.await_quiescent_defer_count = 1;

    InspectorManager::thread_term_removed();

    CHECK_EQUAL(2, snort::rss_capture.await_quiescent_calls);
    CHECK_EQUAL(1, old_counts.tterm);

    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, flow_gadget_release_retries_quiescence_before_tterm)
{
    ReloadCounts old_counts;

    reload_plugin->instantiate(sc.get(), old_counts);
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get());
    CHECK(old_inspector);

    Flow flow;
    flow.set_gadget(old_inspector);
    CHECK_EQUAL(1, get_thread_refs(old_inspector));

    auto reload_sc = start_removal_reload();
    CHECK_EQUAL(1, old_counts.tear_down);
    CHECK_FALSE(old_counts.last_shutdown);

    InspectorManager::thread_term_removed();
    CHECK_EQUAL(0, old_counts.tterm);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    // Exercise the production path: releasing the last flow gadget reference
    // drains the pending tterm.  The first quiescence attempt reports that a
    // callback is still active, so tterm must remain deferred until the next
    // manager drain.
    snort::rss_capture.await_quiescent_defer_count = 1;
    flow.clear_gadget();
    const unsigned tterm_after_gadget_release = old_counts.tterm;
    const unsigned refs_after_gadget_release = get_thread_refs(old_inspector);

    CHECK_EQUAL(0, tterm_after_gadget_release);
    CHECK_EQUAL(1, snort::rss_capture.await_quiescent_calls);

    InspectorManager::thread_drain_pending_tterm();

    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(0, get_thread_refs(old_inspector));

    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);

    CHECK_EQUAL(0, tterm_after_gadget_release);
    CHECK_EQUAL(1, refs_after_gadget_release);
}

TEST(inspector_manager_reload_tests,
    non_inspect_service_change_detaches_both_splitters_before_pending_release)
{
    ReloadCounts old_counts;
    ReloadCounts new_counts;

    reload_plugin->instantiate(sc.get(), old_counts, 10, 11, "old_reload_test");
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get(), 10, 11, "old_reload_test");
    CHECK(old_inspector);

    Flow flow;
    flow.pkt_type = PktType::TCP;
    old_counts.observed_flow = &flow;
    ReloadSession session(&flow);
    flow.session = &session;
    flow.set_gadget(old_inspector);
    session.set_splitter(true, old_inspector->get_splitter(true));
    session.set_splitter(false, old_inspector->get_splitter(false));

    auto reload_sc = start_removal_reload();
    InspectorManager::thread_term_removed();
    reload_plugin->instantiate(reload_sc.get(), new_counts, 10, 11, "new_reload_test");
    InspectorManager::prepare_map();
    Inspector* replacement = reload_plugin->get(
        reload_sc.get(), 10, 11, "new_reload_test");
    CHECK(replacement);
    InspectorManager::thread_init();

    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    ServiceChangeTestContext context =
        { &flow, &session, old_inspector, nullptr, &old_counts, 0 };
    context.stale_to_server_splitter = session.get_splitter(true);
    context.stale_to_client_splitter = session.get_splitter(false);
    service_change_test_context = &context;
    test_data_bus_publish_hook = verify_splitters_safe_during_service_change;

    Packet packet(false);
    packet.flow = &flow;
    InspectorManager::clear_stale_service_inspector_for_test(&packet);

    CHECK_EQUAL(1, context.callbacks);
    CHECK_FALSE(flow.gadget);
    POINTERS_EQUAL(context.fallback_to_server_splitter, session.get_splitter(true));
    POINTERS_EQUAL(context.fallback_to_client_splitter, session.get_splitter(false));
    CHECK(flow.is_inspection_disabled());
    CHECK(flow.flow_state == Flow::FlowState::ALLOW);
    CHECK_EQUAL(0, get_thread_refs(old_inspector));
    CHECK_EQUAL(1, old_counts.tterm);

    InspectorManager::thread_drain_pending_tterm();
    CHECK_EQUAL(1, old_counts.tterm);

    session.set_splitter(true, nullptr);
    session.set_splitter(false, nullptr);

    test_data_bus_publish_hook = nullptr;
    service_change_test_context = nullptr;
    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests,
    inspect_service_change_replaces_safe_fallbacks_before_pending_release)
{
    ReloadCounts old_counts;
    ReloadCounts new_counts;

    reload_plugin->instantiate(sc.get(), old_counts, 10, 11, "old_reload_test");
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get(), 10, 11, "old_reload_test");
    CHECK(old_inspector);

    Flow flow;
    flow.pkt_type = PktType::TCP;
    old_counts.observed_flow = &flow;
    new_counts.observed_flow = &flow;
    ReloadSession session(&flow);
    flow.session = &session;
    flow.set_gadget(old_inspector);
    session.set_splitter(true, old_inspector->get_splitter(true));
    session.set_splitter(false, old_inspector->get_splitter(false));

    auto reload_sc = start_removal_reload();
    InspectorManager::thread_term_removed();
    reload_plugin->instantiate(reload_sc.get(), new_counts, 10, 11, "new_reload_test");
    InspectorManager::prepare_map();
    Inspector* replacement = reload_plugin->get(
        reload_sc.get(), 10, 11, "new_reload_test");
    CHECK(replacement);
    InspectorManager::thread_init();

    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    ServiceChangeTestContext context =
        { &flow, &session, old_inspector, replacement, &old_counts, 0 };
    context.stale_to_server_splitter = session.get_splitter(true);
    context.stale_to_client_splitter = session.get_splitter(false);
    service_change_test_context = &context;
    test_data_bus_publish_hook = verify_splitters_safe_during_service_change;

    Packet packet(false);
    packet.flow = &flow;
    InspectorManager::clear_stale_service_inspector_for_test(&packet);

    CHECK_EQUAL(1, context.callbacks);
    POINTERS_EQUAL(replacement->get_splitter(true), session.get_splitter(true));
    POINTERS_EQUAL(replacement->get_splitter(false), session.get_splitter(false));
    CHECK_EQUAL(0, get_thread_refs(old_inspector));
    CHECK_EQUAL(1, old_counts.tterm);

    InspectorManager::thread_drain_pending_tterm();
    CHECK_EQUAL(1, old_counts.tterm);

    session.set_splitter(true, nullptr);
    session.set_splitter(false, nullptr);
    CHECK_EQUAL(1, new_counts.to_server_splitter_detaches);
    CHECK_EQUAL(1, new_counts.to_client_splitter_detaches);
    CHECK(new_counts.splitters_detached_while_alive);

    test_data_bus_publish_hook = nullptr;
    service_change_test_context = nullptr;
    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests,
    sessionless_stream_service_change_skips_splitters_and_finishes_pending_release)
{
    ReloadCounts old_counts;
    ReloadCounts new_counts;

    reload_plugin->instantiate(sc.get(), old_counts, 10, 11, "old_reload_test");
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get(), 10, 11, "old_reload_test");
    CHECK(old_inspector);

    Flow flow;
    flow.pkt_type = PktType::TCP;
    flow.service = "stale_reload_test";
    old_counts.observed_flow = &flow;
    flow.set_gadget(old_inspector);
    CHECK_FALSE(flow.session);

    auto reload_sc = start_removal_reload();
    InspectorManager::thread_term_removed();
    reload_plugin->instantiate(reload_sc.get(), new_counts, 10, 11, "new_reload_test");
    InspectorManager::prepare_map();
    InspectorManager::thread_init();

    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    ServiceChangeTestContext context =
        { &flow, nullptr, old_inspector, nullptr, &old_counts, 0 };
    service_change_test_context = &context;
    test_data_bus_publish_hook = verify_splitters_safe_during_service_change;

    Packet packet(false);
    packet.flow = &flow;
    InspectorManager::clear_stale_service_inspector_for_test(&packet);

    CHECK_EQUAL(1, context.callbacks);
    CHECK_FALSE(flow.gadget);
    CHECK_FALSE(flow.service);
    CHECK_FALSE(flow.session);
    CHECK(flow.is_inspection_disabled());
    CHECK(flow.flow_state == Flow::FlowState::ALLOW);
    CHECK_EQUAL(0, get_thread_refs(old_inspector));
    CHECK_EQUAL(1, old_counts.tterm);

    InspectorManager::thread_drain_pending_tterm();
    CHECK_EQUAL(1, old_counts.tterm);

    test_data_bus_publish_hook = nullptr;
    service_change_test_context = nullptr;
    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, drain_pending_tterm_without_pending_is_noop)
{
    InspectorManager::thread_drain_pending_tterm();
}

TEST(inspector_manager_reload_tests, duplicate_removed_service_defer_reuses_pending_entry)
{
    ReloadCounts old_counts;

    reload_plugin->instantiate(sc.get(), old_counts);
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get());
    CHECK(old_inspector);

    set_thread_refs(old_inspector, 1);
    auto reload_sc = start_removal_reload();

    InspectorManager::thread_term_removed();
    CHECK_EQUAL(0, old_counts.tterm);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    InspectorManager::thread_term_removed();
    CHECK_EQUAL(0, old_counts.tterm);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    set_thread_refs(old_inspector, 1);
    InspectorManager::thread_drain_pending_tterm();
    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(0, get_thread_refs(old_inspector));

    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, second_removed_service_defer_scans_existing_pending_entry)
{
    ReloadCounts first_counts;
    ReloadCounts second_counts;

    reload_plugin->instantiate(sc.get(), first_counts, 10, 11, "first_reload_test");
    reload_plugin->instantiate(sc.get(), second_counts, 10, 11, "second_reload_test");
    activate_current_map();
    Inspector* first_inspector = reload_plugin->get(sc.get(), 10, 11, "first_reload_test");
    Inspector* second_inspector = reload_plugin->get(sc.get(), 10, 11, "second_reload_test");
    CHECK(first_inspector);
    CHECK(second_inspector);

    set_thread_refs(first_inspector, 1);
    set_thread_refs(second_inspector, 1);
    auto reload_sc = start_removal_reload();

    InspectorManager::thread_term_removed();
    CHECK_EQUAL(0, first_counts.tterm);
    CHECK_EQUAL(0, second_counts.tterm);
    CHECK_EQUAL(2, get_thread_refs(first_inspector));
    CHECK_EQUAL(2, get_thread_refs(second_inspector));

    set_thread_refs(first_inspector, 1);
    set_thread_refs(second_inspector, 1);
    InspectorManager::thread_drain_pending_tterm();
    CHECK_EQUAL(1, first_counts.tterm);
    CHECK_EQUAL(1, second_counts.tterm);
    CHECK_EQUAL(0, get_thread_refs(first_inspector));
    CHECK_EQUAL(0, get_thread_refs(second_inspector));

    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, full_thread_term_marks_pending_tterm_called_before_flush)
{
    ReloadCounts old_counts;

    reload_plugin->instantiate(sc.get(), old_counts);
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get());
    CHECK(old_inspector);

    set_thread_refs(old_inspector, 1);
    auto reload_sc = start_removal_reload();
    InspectorManager::thread_term_removed();
    CHECK_EQUAL(0, old_counts.tterm);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    restore_old_map_for_teardown(reload_sc);
    InspectorManager::thread_term();
    CHECK_EQUAL(1, old_counts.tterm);
    set_thread_refs(old_inspector, 0);
}

// full-shutdown drain must block and retry await_quiescent(), not drop the
// entry; see dev_notes.txt
TEST(inspector_manager_reload_tests, full_thread_term_blocks_until_release_stops_deferring)
{
    ReloadCounts old_counts;

    reload_plugin->instantiate(sc.get(), old_counts);
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get());
    CHECK(old_inspector);

    set_thread_refs(old_inspector, 1);
    auto reload_sc = start_removal_reload();
    InspectorManager::thread_term_removed();
    CHECK_EQUAL(0, old_counts.tterm);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    snort::rss_capture.await_quiescent_defer_count = 3;

    restore_old_map_for_teardown(reload_sc);
    InspectorManager::thread_term();

    CHECK_EQUAL(4, snort::rss_capture.await_quiescent_calls);  // 3 deferred + 1 success
    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(1, get_thread_refs(old_inspector));

    set_thread_refs(old_inspector, 0);
}

TEST(inspector_manager_reload_tests, thread_init_finishes_same_api_pending_when_only_self_hold_remains)
{
    ReloadCounts old_counts;
    ReloadCounts new_counts;

    reload_plugin->instantiate(sc.get(), old_counts, 10, 11, "old_reload_test");
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get(), 10, 11, "old_reload_test");
    CHECK(old_inspector);

    set_thread_refs(old_inspector, 1);
    auto reload_sc = start_removal_reload();
    InspectorManager::thread_term_removed();
    CHECK_EQUAL(0, old_counts.tterm);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    set_thread_refs(old_inspector, 1);
    reload_plugin->instantiate(reload_sc.get(), new_counts, 10, 11, "new_reload_test");
    InspectorManager::prepare_map();
    InspectorManager::thread_init();

    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(1, new_counts.tinit);
    CHECK_EQUAL(0, get_thread_refs(old_inspector));

    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, thread_init_calls_same_api_pending_tterm_but_keeps_live_ref)
{
    ReloadCounts old_counts;
    ReloadCounts new_counts;

    reload_plugin->instantiate(sc.get(), old_counts, 10, 11, "old_reload_test");
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get(), 10, 11, "old_reload_test");
    CHECK(old_inspector);

    set_thread_refs(old_inspector, 1);
    auto reload_sc = start_removal_reload();
    InspectorManager::thread_term_removed();
    CHECK_EQUAL(0, old_counts.tterm);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    reload_plugin->instantiate(reload_sc.get(), new_counts, 10, 11, "new_reload_test");
    InspectorManager::prepare_map();
    InspectorManager::thread_init();

    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(1, new_counts.tinit);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    set_thread_refs(old_inspector, 1);
    InspectorManager::thread_drain_pending_tterm();
    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(0, get_thread_refs(old_inspector));

    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, thread_init_flushes_pending_tterm_under_default_policy)
{
    ReloadCounts old_counts;
    ReloadCounts new_counts;

    reload_plugin->instantiate(sc.get(), old_counts, 10, 11, "old_reload_test");
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get(), 10, 11, "old_reload_test");
    CHECK(old_inspector);

    set_thread_refs(old_inspector, 1);
    auto reload_sc = start_removal_reload();
    InspectorManager::thread_term_removed();
    CHECK_EQUAL(0, old_counts.tterm);

    reload_plugin->instantiate(reload_sc.get(), new_counts, 10, 11, "new_reload_test");
    InspectorManager::prepare_map();

    NetworkPolicy* default_np = reload_sc->policy_map->get_network_policy(0);
    NetworkPolicy* stale_np = reload_sc->policy_map->get_user_network(20);
    CHECK(default_np);
    CHECK(stale_np);
    CHECK(default_np != stale_np);
    set_network_policy(stale_np);

    InspectorManager::thread_init();

    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(1, new_counts.tinit);
    POINTERS_EQUAL(default_np, old_counts.tterm_np);

    set_thread_refs(old_inspector, 1);
    InspectorManager::thread_drain_pending_tterm();
    CHECK_EQUAL(0, get_thread_refs(old_inspector));

    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, thread_init_without_pending_tterm_keeps_current_policy)
{
    ReloadCounts counts;

    reload_plugin->instantiate(sc.get(), counts, 10, 11);
    InspectorManager::prepare_map();

    NetworkPolicy* other_np = sc->policy_map->get_user_network(20);
    CHECK(other_np);
    set_network_policy(other_np);

    InspectorManager::thread_init();

    CHECK_EQUAL(1, counts.tinit);
    POINTERS_EQUAL(other_np, get_network_policy());

    InspectorManager::thread_term();
}

TEST(inspector_manager_reload_tests, same_name_policy_replacement_acknowledges_called_pending_tterm)
{
    ReloadCounts old_counts;
    ReloadCounts new_counts;

    reload_plugin->instantiate(sc.get(), old_counts, 10, 11, "policy_reload_test");
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get(), 10, 11, "policy_reload_test");
    CHECK(old_inspector);

    set_thread_refs(old_inspector, 1);
    auto reload_sc = start_reload();
    reload_plugin->instantiate(reload_sc.get(), new_counts, 10, 12, "policy_reload_test");
    reconcile_reload(reload_sc.get());

    InspectorManager::thread_reinit(reload_sc.get());
    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(1, new_counts.tinit);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    InspectorManager::thread_term_removed();
    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(2, get_thread_refs(old_inspector));

    set_thread_refs(old_inspector, 1);
    InspectorManager::thread_drain_pending_tterm();
    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(0, get_thread_refs(old_inspector));

    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, register_reload_survivor_handlers_invoked_with_matching_policy)
{
    ReloadCounts old_counts;

    reload_plugin->instantiate(sc.get(), old_counts);
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get());
    CHECK(old_inspector);

    // Hold a thread ref so the inspector survives reload and reconcile_map
    // takes the deferred-tterm + RSS-construction path.
    set_thread_refs(old_inspector, 1);
    auto reload_sc = start_removal_reload();
    CHECK_EQUAL(1, old_counts.tear_down);

    // Dropped-inspector loop constructs one RSS bound to the new-SC policies;
    // list_survivors() is empty here so the for_each loop adds nothing.
    CHECK_EQUAL(1, snort::rss_capture.ctor_calls);

    NetworkPolicy* expected_np = reload_sc->policy_map->get_user_network(10);
    CHECK(expected_np);
    POINTERS_EQUAL(expected_np, snort::rss_capture.last_np);

    InspectionPolicy* expected_ip = expected_np->get_user_inspection_policy(11);
    CHECK(expected_ip);
    POINTERS_EQUAL(expected_ip, snort::rss_capture.last_ip);

    POINTERS_EQUAL(old_inspector, snort::rss_capture.last_survivor);

    // Drain refs and clean up like the deferred-tterm tests above.
    set_thread_refs(old_inspector, 1);
    InspectorManager::thread_term_removed();
    set_thread_refs(old_inspector, 1);
    InspectorManager::thread_drain_pending_tterm();
    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, newly_removed_survivor_registered_once_per_reload)
{
    ReloadCounts old_counts;
    ReloadCounts carried_counts;
    ReloadInspector carried_survivor(&carried_counts);

    reload_plugin->instantiate(sc.get(), old_counts);
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get());
    CHECK(old_inspector);

    // Keep the inspector alive through the reload.  Seed the test resweep
    // with the same inspector that the dropped-inspector pass registers;
    // before the fix this makes reconcile_map() invoke the callback twice.
    set_thread_refs(old_inspector, 1);
    snort::rss_capture.survivors.push_back({ old_inspector, 10, 11 });
    snort::rss_capture.survivors.push_back({ &carried_survivor, 10, 11 });

    auto reload_sc = start_removal_reload();

    CHECK_EQUAL(1, old_counts.survivor_handler_registrations);
    CHECK_EQUAL(1, carried_counts.survivor_handler_registrations);
    CHECK_EQUAL(2, snort::rss_capture.end_reconcile_calls);

    set_thread_refs(old_inspector, 1);
    InspectorManager::thread_term_removed();
    set_thread_refs(old_inspector, 1);
    InspectorManager::thread_drain_pending_tterm();
    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, register_reload_survivor_handlers_skipped_when_policy_missing)
{
    const uint64_t baseline = snort::rss_stats.policy_resolution_failures.load();
    ReloadCounts old_counts;

    reload_plugin->instantiate(sc.get(), old_counts);
    activate_current_map();
    Inspector* old_inspector = reload_plugin->get(sc.get());
    CHECK(old_inspector);

    set_thread_refs(old_inspector, 1);

    // Build a reload SC like start_removal_reload does, but break the
    // user-id lookup for the inspector's InspectionPolicy in the new SC
    // before reconcile runs.  This drives reconcile_map's
    //     if ( new_np and new_ip )
    // gate to false: new_np resolves, new_ip does not, so RSS construction
    // is skipped and the inspector still gets dropped via deferred-tterm.
    InspectorManager::new_map();
    std::unique_ptr<SnortConfig> reload_sc(new SnortConfig);

    NetworkPolicy* matching_np = reload_sc->policy_map->get_user_network(10);
    CHECK(matching_np);
    matching_np->user_inspection.erase(11);

    InspectorManager::prepare_map();
    InspectorManager::reconcile_map(reload_sc.get());

    CHECK_EQUAL(0, snort::rss_capture.ctor_calls);
    CHECK_EQUAL(1, old_counts.tear_down);
    CHECK_EQUAL(baseline + 1, snort::rss_stats.policy_resolution_failures.load());

    // Inspection-policy lookup is the one that failed here (network resolves).
    CHECK(last_warning_message.find("resolve its inspection policy") != std::string::npos);

    // Drain refs and clean up like the deferred-tterm tests above.
    set_thread_refs(old_inspector, 1);
    InspectorManager::thread_term_removed();
    set_thread_refs(old_inspector, 1);
    InspectorManager::thread_drain_pending_tterm();
    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);
}

// Companion to the case above: this time the *network* policy lookup is the
// one that fails (survivor's np_user_id doesn't exist in the new config at
// all), so the diagnostic must name "network", not "inspection".
TEST(inspector_manager_reload_tests, policy_resolve_failure_warning_names_network_lookup)
{
    const uint64_t baseline = snort::rss_stats.policy_resolution_failures.load();

    ReloadCounts dummy_counts;
    ReloadInspector fake_survivor(&dummy_counts);
    snort::rss_capture.survivors.push_back({ &fake_survivor, 999, 11 });

    InspectorManager::new_map();
    std::unique_ptr<SnortConfig> reload_sc(new SnortConfig);
    CHECK(!reload_sc->policy_map->get_user_network(999));

    InspectorManager::prepare_map();
    InspectorManager::reconcile_map(reload_sc.get());

    CHECK_EQUAL(0, snort::rss_capture.ctor_calls);
    CHECK_EQUAL(baseline + 1, snort::rss_stats.policy_resolution_failures.load());
    CHECK(last_warning_message.find("resolve its network policy") != std::string::npos);
    CHECK(last_warning_message.find("resolve its inspection policy") == std::string::npos);

    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, removing_global_inspector_is_not_a_policy_resolve_failure)
{
    const uint64_t baseline = snort::rss_stats.policy_resolution_failures.load();
    ReloadCounts old_counts;

    alt_plugin.reset(new ReloadPlugin("global_reload_test", Module::GLOBAL, IT_PASSIVE));
    alt_plugin->instantiate(sc.get(), old_counts);
    activate_current_map();

    last_warning_message.clear();
    std::unique_ptr<SnortConfig> reload_sc = start_removal_reload();

    CHECK_EQUAL(1, old_counts.tear_down);
    CHECK_EQUAL(0, snort::rss_capture.ctor_calls);

    CHECK_EQUAL(baseline, snort::rss_stats.policy_resolution_failures.load());
    CHECK(last_warning_message.find("RSS: survivor") == std::string::npos);

    restore_old_map_for_teardown(reload_sc);
}

TEST(inspector_manager_reload_tests, removing_context_inspector_is_not_a_policy_resolve_failure)
{
    const uint64_t baseline = snort::rss_stats.policy_resolution_failures.load();
    ReloadCounts old_counts;

    alt_plugin.reset(new ReloadPlugin("context_reload_test", Module::CONTEXT, IT_PACKET));
    alt_plugin->instantiate(sc.get(), old_counts);
    activate_current_map();

    last_warning_message.clear();
    std::unique_ptr<SnortConfig> reload_sc = start_removal_reload();

    CHECK_EQUAL(1, old_counts.tear_down);
    CHECK_EQUAL(0, snort::rss_capture.ctor_calls);

    CHECK_EQUAL(baseline, snort::rss_stats.policy_resolution_failures.load());
    CHECK(last_warning_message.find("RSS: survivor") == std::string::npos);

    restore_old_map_for_teardown(reload_sc);
}

// A survivor from an earlier reload (absent from both prev_iv and curr_iv
// now) must still get re-attached on every later reconcile_map -- the
// dropped-inspector loop can't see it, only the for_each-survivor loop can.
// Exercises that loop in isolation: prev_iv empty, rss_capture.survivors
// seeded with a fake survivor matching an entry in the new SC's PolicyMap.
TEST(inspector_manager_reload_tests, reconcile_map_reattaches_carried_survivors)
{
    // Empty prev_iv: no inspector instantiated.  The dropped-inspector
    // loop in reconcile_map will iterate zero entries, so any RSS ctor
    // call observed here is attributable to the for_each-survivor loop.
    ReloadCounts dummy_counts;
    ReloadInspector fake_survivor(&dummy_counts);

    InspectorManager::new_map();
    std::unique_ptr<SnortConfig> reload_sc(new SnortConfig);

    snort::rss_capture.survivors.push_back({ &fake_survivor, 10, 11 });

    InspectorManager::prepare_map();
    InspectorManager::reconcile_map(reload_sc.get());

    CHECK_EQUAL(1, snort::rss_capture.ctor_calls);

    NetworkPolicy* expected_np = reload_sc->policy_map->get_user_network(10);
    CHECK(expected_np);
    POINTERS_EQUAL(expected_np, snort::rss_capture.last_np);

    InspectionPolicy* expected_ip = expected_np->get_user_inspection_policy(11);
    CHECK(expected_ip);
    POINTERS_EQUAL(expected_ip, snort::rss_capture.last_ip);

    POINTERS_EQUAL(&fake_survivor, snort::rss_capture.last_survivor);

    // the configuration the reload ran on top of, not the incoming stub_reload_id
    CHECK_EQUAL(stub_active_reload_id, snort::rss_capture.last_list_reload_id);

    restore_old_map_for_teardown(reload_sc);
}

// A carried-over survivor whose matching policy is GONE from the new SC
// must be skipped by the for_each loop (no RSS construction).  This is
// the "graceful drain" path: surviving flows continue to drain via
// FLOW_NO_SERVICE on the new SC's default policy but no new survivor
// handlers are attached.
TEST(inspector_manager_reload_tests, reconcile_map_skips_carried_survivors_when_policy_missing)
{
    const uint64_t baseline = snort::rss_stats.policy_resolution_failures.load();
    ReloadCounts dummy_counts;
    ReloadInspector fake_survivor(&dummy_counts);

    InspectorManager::new_map();
    std::unique_ptr<SnortConfig> reload_sc(new SnortConfig);

    // Remove the matching InspectionPolicy from the new SC so the
    // for_each loop's new_ip resolution fails for the seeded survivor.
    NetworkPolicy* matching_np = reload_sc->policy_map->get_user_network(10);
    CHECK(matching_np);
    matching_np->user_inspection.erase(11);

    snort::rss_capture.survivors.push_back({ &fake_survivor, 10, 11 });

    InspectorManager::prepare_map();
    InspectorManager::reconcile_map(reload_sc.get());

    CHECK_EQUAL(0, snort::rss_capture.ctor_calls);
    CHECK_EQUAL(baseline + 1, snort::rss_stats.policy_resolution_failures.load());

    restore_old_map_for_teardown(reload_sc);
}

// Many-reload validation for the carried-survivor resolve-failure path,
// standing in for a sustained SIT-style run without needing real traffic:
// the same survivor's policy stays missing across many reload cycles, so
// RSS construction must never fire and every cycle must add exactly one
// resolve failure -- proving the counter accumulates correctly rather
// than double-counting or silently dropping cycles.
TEST(inspector_manager_reload_tests, many_reloads_with_missing_policy_accumulate_resolve_failures)
{
    const uint64_t baseline = snort::rss_stats.policy_resolution_failures.load();
    constexpr unsigned CYCLE_COUNT = 500;

    ReloadCounts dummy_counts;
    ReloadInspector fake_survivor(&dummy_counts);
    snort::rss_capture.survivors.push_back({ &fake_survivor, 10, 11 });

    for ( unsigned i = 0; i < CYCLE_COUNT; i++ )
    {
        InspectorManager::new_map();
        std::unique_ptr<SnortConfig> reload_sc(new SnortConfig);

        NetworkPolicy* matching_np = reload_sc->policy_map->get_user_network(10);
        CHECK(matching_np);
        matching_np->user_inspection.erase(11);

        InspectorManager::prepare_map();
        InspectorManager::reconcile_map(reload_sc.get());

        CHECK_EQUAL(0, snort::rss_capture.ctor_calls);  // never once constructed
        CHECK_EQUAL(baseline + i + 1, snort::rss_stats.policy_resolution_failures.load());
        CHECK(last_warning_message.find("resolve its inspection policy") != std::string::npos);

        // restore_old_map_for_teardown() only calls revert_map(), which
        // leaves prev_iv non-null (fine for a one-shot test, since
        // teardown() unconditionally cleans up after). A repeated loop
        // needs restore_map()'s prev_iv=nullptr so new_map()'s
        // assert(!prev_iv) holds on the next cycle.
        reload_sc.reset();
        InspectorManager::restore_map();
    }
    mock().setDataObject("snort_config", "const SnortConfig", sc.get());
}

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
