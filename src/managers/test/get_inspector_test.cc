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
// get_inspector_test.cc author Ron Dempster <rdempste@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
void PacketTracer::log(const char*, ...) {}

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

class TestModule : public Module
{
public:
    TestModule(const char* s, Module::Usage u) : Module(s, "help")
    { usage = u; }

    ~TestModule() override = default;

    Usage get_usage() const override
    { return usage; }

    static Module* ctor() { return nullptr; }
    static void dtor(Module*) { }

protected:
    Usage usage;
};

class TestInspector : public Inspector
{
public:
    TestInspector()
    { }
};

static Inspector* ins_ctor(Module*)
{ return new TestInspector; }

static void ins_dtor(Inspector* pin)
{ delete pin; }

static const InspectApi test_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,    // plug version
        PLUGIN_DEFAULT,
        API_OPTIONS,
        "name",
        "help",
        TestModule::ctor,
        TestModule::dtor,
    },
    IT_PASSIVE,
    PROTO_BIT__NONE,
    nullptr,  // buffers
    nullptr,  // service
    nullptr,  // pinit
    nullptr,  // pterm
    nullptr,  // tinit
    nullptr,  // tterm
    ins_ctor,
    ins_dtor,
    nullptr,  // ssn
    nullptr   // reset
};

struct TestApi
{
    InspectApi* api;

    TestApi(const char* name, InspectorType it, const char* svc)
    {
        api = new InspectApi(test_api);
        api->base.name = name;
        api->type = it;
        api->service = svc;
    }
    ~TestApi()
    { delete api; }
};

//--------------------------------------------------------------------------
// test data
//--------------------------------------------------------------------------

struct TestData
{
    const char* name;
    Module::Usage use;
    InspectorType type;

    uint64_t npid = 0;
    uint64_t ipid = 0;

    const char* service = nullptr;
    const char* alias = nullptr;

    TestModule* mod = nullptr;
    TestApi* api = nullptr;

    PlugInterface* plug = nullptr;
    PlugContext* context = nullptr;
};

static std::vector<TestData> tests =
{
    { "appid", Module::GLOBAL, IT_CONTROL },
    { "file_inspect", Module::GLOBAL, IT_PASSIVE },
    { "perf_monitor", Module::GLOBAL, IT_PROBE },
    { "stream", Module::GLOBAL, IT_STREAM },

    { "normalizer", Module::CONTEXT, IT_PACKET, 10 },
    { "reputation", Module::CONTEXT, IT_PASSIVE, 10 },
    { "rna", Module::CONTEXT, IT_CONTROL, 20 },

    { "http_inspect", Module::INSPECT, IT_SERVICE, 10, 11, "http" },
    // aliased inspectors must be after the unaliased instance
    { "http_inspect", Module::INSPECT, IT_SERVICE, 10, 11, "http", "http_inspect1011" },
    { "http_inspect", Module::INSPECT, IT_SERVICE, 10, 12, "http", "http_inspect1012" },
    { "http_inspect", Module::INSPECT, IT_SERVICE, 20, 21, "http", "http_inspect2021" },
    { "http_inspect", Module::INSPECT, IT_SERVICE, 20, 22, "http", "http_inspect2022" },

    { "back_orifice", Module::INSPECT, IT_NETWORK, 10, 12 },
    { "binder", Module::INSPECT, IT_PASSIVE, 10, 12 },

    { "stream_tcp", Module::INSPECT, IT_STREAM, 20, 21 },
    { "wizard", Module::INSPECT, IT_SERVICE, 20, 22 },
};

static void setup_test_data()
{
    const char* prior = "";

    for ( auto& td : tests )
    {
        if ( !strcmp(td.name, prior) )
            continue;

        td.mod = new TestModule(td.name, td.use);
        td.api = new TestApi(td.name, td.type, td.service);

        td.plug = InspectorManager::get_interface(td.api->api);
        td.context = td.plug->get_context();
        mock().setDataObject(td.name, "PlugContext", td.context);

        prior = td.name;
    }
}

static void clear_test_data()
{
    for ( const auto& td : tests )
    {
        delete td.context;
        delete td.plug;
        delete td.api;
        delete td.mod;
    }
}

static void set_policies(const SnortConfig* sc, const TestData& td)
{
    if ( auto* np = sc->policy_map->get_user_network(td.npid) )
    {
        set_network_policy(np);

        if ( auto* ip = np->get_user_inspection_policy(td.ipid) )
            set_inspection_policy(ip);
    }
}

static TestData* get_data(const char* s)
{
    for ( auto& td : tests )
    {
        if ( !strcmp(td.name, s) )
            return &td;
    }
    assert(false);
    return nullptr;
}

static void instantiate(SnortConfig* sc)
{
    for ( auto& td : tests )
    {
        set_policies(sc, td);
        TestData* otd = td.alias ? get_data(td.name) : &td;
        otd->plug->instantiate(otd->mod, sc, td.alias);
    }
}

static void validate(const SnortConfig* sc)
{
    for ( const auto& td : tests )
    {
        set_policies(sc, td);
        const char* key = td.alias ? td.alias : td.name;
        Inspector* pin = InspectorManager::get_inspector(key, td.use);
        CHECK(pin);
        CHECK(!strcmp(pin->get_alias_name(), key));
    }
}

//--------------------------------------------------------------------------
// unit tests
//--------------------------------------------------------------------------

TEST_GROUP(get_inspector_tests)
{
    SnortConfig* sc = nullptr;

    void setup() override
    {
        InspectorManager::new_map();
        // cppcheck-suppress unreadVariable
        sc = new SnortConfig;
    }

    void teardown() override
    {
        delete sc;
        InspectorManager::empty_trash();
        InspectorManager::cleanup();
    }
};

TEST(get_inspector_tests, basic)
{
    instantiate(sc);

    InspectorManager::prepare_map();
    InspectorManager::configure(sc);

    validate(sc);
}

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    setup_test_data();
    int r = CommandLineTestRunner::RunAllTests(argc, argv);
    clear_test_data();
    return r;
}
