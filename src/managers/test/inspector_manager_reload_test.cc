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

SnortConfig::SnortConfig(const char*)
{
    policy_map = new PolicyMap();
    mock().setDataObject("snort_config", "const SnortConfig", this);
}

SnortConfig::~SnortConfig()
{
    delete policy_map;
}

const SnortConfig* SnortConfig::get_conf()
{ return (const SnortConfig*)mock().getData("snort_config").getObjectPointer(); }

unsigned SnortConfig::get_reload_id() { return 0; }

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
    bool last_shutdown = false;
};

class ReloadModule : public Module
{
public:
    explicit ReloadModule(const char* s) : Module(s, "reload test inspector")
    { }

    Usage get_usage() const override
    { return Module::INSPECT; }

    static Module* ctor() { return nullptr; }
    static void dtor(Module*) { }

    ReloadCounts* reload_counts = nullptr;
};

class ReloadInspector : public Inspector
{
public:
    explicit ReloadInspector(ReloadCounts* c) : counts(c)
    { }

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
    { ++counts->tterm; }

private:
    ReloadCounts* counts = nullptr;
};

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
    explicit ReloadPlugin(const char* name) : module(name), api(reload_api_template)
    {
        api.base.name = name;
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

    void setup() override
    {
        InspectorManager::new_map();
        sc.reset(new SnortConfig);
        reload_plugin.reset(new ReloadPlugin("reload_test"));
    }

    void teardown() override
    {
        sc.reset();
        InspectorManager::empty_trash();
        InspectorManager::cleanup();
        reload_plugin.reset();
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

    void reconcile_reload(SnortConfig* reload_sc)
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

TEST(inspector_manager_reload_tests, flow_gadget_release_drains_pending_tterm)
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

    flow.clear_gadget();
    const unsigned tterm_after_gadget_release = old_counts.tterm;
    const unsigned refs_after_gadget_release = get_thread_refs(old_inspector);

    if ( !old_counts.tterm )
        InspectorManager::thread_drain_pending_tterm();

    CHECK_EQUAL(1, old_counts.tterm);
    CHECK_EQUAL(0, get_thread_refs(old_inspector));

    InspectorManager::thread_term();
    restore_old_map_for_teardown(reload_sc);

    CHECK_EQUAL(1, tterm_after_gadget_release);
    CHECK_EQUAL(0, refs_after_gadget_release);
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

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
