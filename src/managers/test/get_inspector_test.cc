//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
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

#include <unordered_map>

#include "get_inspector_stubs.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

bool Inspector::is_inactive() { return true; }

NetworkPolicy* snort::get_network_policy()
{ return (NetworkPolicy*)mock().getData("network_policy").getObjectPointer(); }
NetworkPolicy* PolicyMap::get_user_network(uint64_t) const
{ return (NetworkPolicy*)mock().getData("network_policy").getObjectPointer(); }
InspectionPolicy* snort::get_inspection_policy()
{ return (InspectionPolicy*)mock().getData("inspection_policy").getObjectPointer(); }
InspectionPolicy* NetworkPolicy::get_user_inspection_policy(uint64_t) const
{ return (InspectionPolicy*)mock().getData("inspection_policy").getObjectPointer(); }

InspectionPolicy::InspectionPolicy(PolicyId)
{ InspectorManager::new_policy(this, nullptr); }
InspectionPolicy::~InspectionPolicy()
{ InspectorManager::delete_policy(this, false); }
NetworkPolicy::NetworkPolicy(PolicyId, PolicyId)
{ InspectorManager::new_policy(this, nullptr); }
NetworkPolicy::~NetworkPolicy()
{
    for ( auto p : inspection_policy )
        delete p;

    InspectorManager::delete_policy(this, false);
    inspection_policy.clear();
}
PolicyMap::PolicyMap(PolicyMap*, const char*)
{
    empty_ips_policy = nullptr;
    inspector_tinit_complete = nullptr;
    file_id = InspectorManager::create_single_instance_inspector_policy();
    flow_tracking = InspectorManager::create_single_instance_inspector_policy();
    global_inspector_policy = InspectorManager::create_global_inspector_policy();
    NetworkPolicy* np = new NetworkPolicy(network_policy.size(), 0);
    network_policy.push_back(np);
    InspectionPolicy* ip = new InspectionPolicy();
    np->inspection_policy.push_back(ip);
}
PolicyMap::~PolicyMap()
{
    InspectorManager::destroy_single_instance_inspector(file_id);
    InspectorManager::destroy_single_instance_inspector(flow_tracking);
    InspectorManager::destroy_global_inspector_policy(global_inspector_policy, false);
    for ( auto p : network_policy )
        delete p;
}
SnortConfig::SnortConfig(const SnortConfig* const, const char*)
{
    policy_map = new PolicyMap();
    InspectorManager::new_config(this);
}
SnortConfig::~SnortConfig()
{
    InspectorManager::delete_config(this);
    delete policy_map;
}
const SnortConfig* SnortConfig::get_conf()
{ return (const SnortConfig*)mock().getData("snort_config").getObjectPointer(); }

Module::Module(const char* name, const char*) : name(name), help(nullptr), params(nullptr), list(false)
{ }

class TestInspector : public Inspector
{
public:
    TestInspector() = default;
    ~TestInspector() override = default;
    void eval(Packet*) override { }
};

class TestModule : public Module
{
public:
    TestModule(const char* name, Module::Usage usage) : Module(name, ""), usage(usage)
    { }
    ~TestModule() override = default;
    Usage get_usage() const override
    { return usage; }

protected:
    Usage usage;
};


static Inspector* test_ctor(Module* mod)
{
    std::unordered_map<Module*, Inspector*>* mod_to_ins =
        (std::unordered_map<Module*, Inspector*>*)mock().getData("mod_to_ins").getObjectPointer();
    auto it = mod_to_ins->find(mod);
    return it == mod_to_ins->end() ? nullptr : it->second;
}

static void test_dtor(Inspector*)
{ }

#define DECLARE_ENTRY(NAME, USAGE) \
    static TestModule NAME##_mod(#NAME, USAGE); \
    static InspectApi NAME##_api; \
    static TestInspector NAME##_ins

DECLARE_ENTRY(binder, Module::Usage::INSPECT);

DECLARE_ENTRY(file, Module::Usage::GLOBAL);
DECLARE_ENTRY(stream, Module::Usage::GLOBAL);

DECLARE_ENTRY(global_passive, Module::Usage::GLOBAL);
DECLARE_ENTRY(global_probe, Module::Usage::GLOBAL);
DECLARE_ENTRY(global_control, Module::Usage::GLOBAL);

DECLARE_ENTRY(context_passive, Module::Usage::CONTEXT);
DECLARE_ENTRY(context_packet, Module::Usage::CONTEXT);
DECLARE_ENTRY(context_first, Module::Usage::CONTEXT);
DECLARE_ENTRY(context_control, Module::Usage::CONTEXT);

DECLARE_ENTRY(inspect_passive, Module::Usage::INSPECT);
DECLARE_ENTRY(inspect_packet, Module::Usage::INSPECT);
DECLARE_ENTRY(inspect_network, Module::Usage::INSPECT);
DECLARE_ENTRY(inspect_service, Module::Usage::INSPECT);
DECLARE_ENTRY(inspect_stream, Module::Usage::INSPECT);
DECLARE_ENTRY(inspect_wizard, Module::Usage::INSPECT);

#define ADD_ENTRY(NAME, TYPE) \
    do { \
        NAME##_api = {}; \
        NAME##_api.base.name = NAME##_mod.get_name(); \
        NAME##_api.type = TYPE; \
        NAME##_api.ctor = test_ctor; \
        NAME##_api.dtor = test_dtor; \
        NAME##_ins.set_api(&NAME##_api); \
        InspectorManager::add_plugin(&NAME##_api); \
    } while (0)

#define INSTANTIATE(NAME) \
    do { \
        mod_to_ins[&NAME##_mod] = &NAME##_ins; \
        InspectorManager::instantiate(&NAME##_api, &NAME##_mod, sc, NAME##_mod.get_name()); \
    } while (0)

void setup_test_globals()
{
    ADD_ENTRY(binder, IT_PASSIVE);

    ADD_ENTRY(file, IT_FILE);
    ADD_ENTRY(stream, IT_STREAM);

    ADD_ENTRY(global_passive, IT_PASSIVE);
    ADD_ENTRY(global_probe, IT_PROBE);
    ADD_ENTRY(global_control, IT_CONTROL);

    ADD_ENTRY(context_passive, IT_PASSIVE);
    ADD_ENTRY(context_packet, IT_PACKET);
    ADD_ENTRY(context_first, IT_FIRST);
    ADD_ENTRY(context_control, IT_CONTROL);

    ADD_ENTRY(inspect_passive, IT_PASSIVE);
    ADD_ENTRY(inspect_packet, IT_PACKET);
    ADD_ENTRY(inspect_network, IT_NETWORK);
    ADD_ENTRY(inspect_service, IT_SERVICE);
    ADD_ENTRY(inspect_stream, IT_STREAM);
    ADD_ENTRY(inspect_wizard, IT_WIZARD);
}

TEST_GROUP(get_inspector_tests)
{
    SnortConfig* sc;
    std::unordered_map<Module*, Inspector*> mod_to_ins;

    void setup() override
    {
        sc = new SnortConfig;
        mock().setDataObject("snort_config", "const SnortConfig", sc);
        mock().setDataObject("mod_to_ins", "std::unordered_map<Module*, Inspector*>", &mod_to_ins);
        NetworkPolicy* np = sc->policy_map->get_network_policy();
        mock().setDataObject("network_policy", "NetworkPolicy", np);
        InspectionPolicy* ip = np->get_inspection_policy();
        mock().setDataObject("inspection_policy", "InspectionPolicy", ip);

        INSTANTIATE(binder);

        INSTANTIATE(file);
        INSTANTIATE(stream);

        INSTANTIATE(global_passive);
        INSTANTIATE(global_probe);
        INSTANTIATE(global_control);

        INSTANTIATE(context_passive);
        INSTANTIATE(context_packet);
        INSTANTIATE(context_first);
        INSTANTIATE(context_control);

        INSTANTIATE(inspect_passive);
        INSTANTIATE(inspect_packet);
        INSTANTIATE(inspect_network);
        INSTANTIATE(inspect_service);
        INSTANTIATE(inspect_stream);
        INSTANTIATE(inspect_wizard);

        InspectorManager::configure(sc, false);
    }

    void teardown() override
    {
        delete sc;
        InspectorManager::empty_trash();
        mod_to_ins.clear();
        mock().clear();
    }
};

#define THE_TEST(NAME, USAGE, TYPE) \
    do { \
        Inspector* ins = InspectorManager::get_inspector(NAME##_mod.get_name(), USAGE, TYPE); \
        CHECK_TEXT(&NAME##_ins == ins, "Did not find the " #NAME " inspector"); \
        STRCMP_EQUAL_TEXT(ins->get_name(), NAME##_mod.get_name(), "Inspector name is not " #NAME); \
        ins = InspectorManager::get_inspector("not_" #NAME, USAGE, TYPE); \
        CHECK_TEXT(nullptr == ins, "Found the not_" #NAME " inspector"); \
    } while (0)

TEST(get_inspector_tests, file)
{
    THE_TEST(file, Module::Usage::GLOBAL, IT_FILE);
}

TEST(get_inspector_tests, stream)
{
    THE_TEST(stream, Module::Usage::GLOBAL, IT_STREAM);
}

TEST(get_inspector_tests, global_passive)
{
    THE_TEST(global_passive, Module::Usage::GLOBAL, IT_PASSIVE);
}

TEST(get_inspector_tests, global_probe)
{
    THE_TEST(global_probe, Module::Usage::GLOBAL, IT_PROBE);
}

TEST(get_inspector_tests, global_control)
{
    THE_TEST(global_control, Module::Usage::GLOBAL, IT_CONTROL);
}

TEST(get_inspector_tests, context_passive)
{
    THE_TEST(context_passive, Module::Usage::CONTEXT, IT_PASSIVE);
}

TEST(get_inspector_tests, context_packet)
{
    THE_TEST(context_packet, Module::Usage::CONTEXT, IT_PACKET);
}

TEST(get_inspector_tests, context_first)
{
    THE_TEST(context_first, Module::Usage::CONTEXT, IT_FIRST);
}

TEST(get_inspector_tests, context_control)
{
    THE_TEST(context_control, Module::Usage::CONTEXT, IT_CONTROL);
}

TEST(get_inspector_tests, inspect_passive)
{
    THE_TEST(inspect_passive, Module::Usage::INSPECT, IT_PASSIVE);
}

TEST(get_inspector_tests, inspect_packet)
{
    THE_TEST(inspect_packet, Module::Usage::INSPECT, IT_PACKET);
}

TEST(get_inspector_tests, inspect_network)
{
    THE_TEST(inspect_network, Module::Usage::INSPECT, IT_NETWORK);
}

TEST(get_inspector_tests, inspect_service)
{
    THE_TEST(inspect_service, Module::Usage::INSPECT, IT_SERVICE);
}

TEST(get_inspector_tests, inspect_stream)
{
    THE_TEST(inspect_stream, Module::Usage::INSPECT, IT_STREAM);
}

TEST(get_inspector_tests, inspect_wizard)
{
    THE_TEST(inspect_wizard, Module::Usage::INSPECT, IT_WIZARD);
}

int main(int argc, char** argv)
{
    setup_test_globals();
    int r = CommandLineTestRunner::RunAllTests(argc, argv);
    InspectorManager::release_plugins();
    return r;
}
