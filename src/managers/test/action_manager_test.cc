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
// action_manager_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdlib>
#include <cstring>

#include "framework/ips_action.h"
#include "framework/module.h"
#include "main/snort_config.h"
#include "main/thread_config.h"
#include "managers/action_manager.h"
#include "managers/plug_interface.h"
#include "managers/plugin_manager.h"
#include "parser/parser.h"
#include "utils/dnet_header.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

static unsigned parse_errors = 0;
static PlugInterface* action_plugin = nullptr;
static unsigned action_ctor_calls = 0;
static unsigned action_dtor_calls = 0;
static unsigned module_ctor_calls = 0;
static unsigned module_dtor_calls = 0;
static std::string configured_page;

namespace snort
{
SnortConfig::SnortConfig(const char*) { }
SnortConfig::~SnortConfig() = default;

char* snort_strdup(const char* s)
{ return s ? strdup(s) : nullptr; }

unsigned get_instance_id()
{ return 0; }

unsigned ThreadConfig::get_instance_max()
{ return 1; }

void ParseError(const char*, ...)
{ parse_errors++; }

IpsPolicy* get_ips_policy()
{ return nullptr; }
}

RuleListNode* CreateRuleType(SnortConfig*, const char*, IpsAction::Type)
{ return nullptr; }

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }

extern "C" int addr_pton(const char*, struct addr*)
{ return -1; }

class TestAction : public IpsAction
{
public:
    TestAction() : IpsAction("test_action", nullptr) { }
    void exec(Packet*, const ActInfo&) override { }
};

class TestActionModule : public Module
{
public:
    explicit TestActionModule(const Parameter* params) :
        Module("test_action", "test action", params)
    { }

    bool set(const char*, Value& v, SnortConfig*) override
    {
        configured_page = v.get_string();
        return true;
    }
};

static const Parameter page_params[] =
{
    { "page", Parameter::PT_STRING, nullptr, nullptr, "page file" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter other_params[] =
{
    { "other", Parameter::PT_STRING, nullptr, nullptr, "other parameter" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static Module* make_page_module()
{
    module_ctor_calls++;
    return new TestActionModule(page_params);
}

static Module* make_other_module()
{
    module_ctor_calls++;
    return new TestActionModule(other_params);
}

static void delete_module(Module* m)
{
    module_dtor_calls++;
    delete m;
}

static IpsAction* make_action(Module*)
{
    action_ctor_calls++;
    return new TestAction;
}

static void delete_action(IpsAction* a)
{
    action_dtor_calls++;
    delete a;
}

static ActionApi page_action_api =
{
    {
        PT_IPS_ACTION,
        sizeof(ActionApi),
        ACTAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "test_action",
        "test action",
        make_page_module,
        delete_module
    },
    IpsAction::IAP_OTHER,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    make_action,
    delete_action
};

static ActionApi no_module_action_api =
{
    {
        PT_IPS_ACTION,
        sizeof(ActionApi),
        ACTAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "test_action",
        "test action",
        nullptr,
        nullptr
    },
    IpsAction::IAP_OTHER,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    make_action,
    delete_action
};

static ActionApi other_param_action_api =
{
    {
        PT_IPS_ACTION,
        sizeof(ActionApi),
        ACTAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "test_action",
        "test action",
        make_other_module,
        delete_module
    },
    IpsAction::IAP_OTHER,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    make_action,
    delete_action
};

static ActionApi page_action_without_module_dtor_api =
{
    {
        PT_IPS_ACTION,
        sizeof(ActionApi),
        ACTAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "test_action",
        "test action",
        make_page_module,
        nullptr
    },
    IpsAction::IAP_OTHER,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    make_action,
    delete_action
};

PlugInterface* PluginManager::get_interface(const char* name)
{ return !strcmp(name, "test_action") ? action_plugin : nullptr; }

void PluginManager::set_instantiated(const char*) { }

unsigned PluginManager::for_each(PlugType, PlugFunc, void*)
{ return 0; }

static void reset_test_state()
{
    parse_errors = 0;
    action_ctor_calls = 0;
    action_dtor_calls = 0;
    module_ctor_calls = 0;
    module_dtor_calls = 0;
    configured_page.clear();
    delete action_plugin;
    action_plugin = nullptr;
}

TEST_GROUP(action_manager_configured_action)
{
    void setup() override
    { reset_test_state(); }

    void teardown() override
    { reset_test_state(); }
};

TEST(action_manager_configured_action, rejects_unknown_action)
{
    SnortConfig sc;
    ActionManager::new_config(&sc);

    const IpsAction* action = ActionManager::instantiate_action_with_param(
        "missing_action", "page", "page.html", &sc);

    CHECK(action == nullptr);
    CHECK_EQUAL(1, parse_errors);
    CHECK_EQUAL(0, action_ctor_calls);
    ActionManager::delete_config(&sc);
}

TEST(action_manager_configured_action, rejects_action_without_module)
{
    SnortConfig sc;
    ActionManager::new_config(&sc);
    action_plugin = ActionManager::get_interface(&no_module_action_api);

    const IpsAction* action = ActionManager::instantiate_action_with_param(
        "test_action", "page", "page.html", &sc);

    CHECK(action == nullptr);
    CHECK_EQUAL(1, parse_errors);
    CHECK_EQUAL(0, module_ctor_calls);
    CHECK_EQUAL(0, action_ctor_calls);
    ActionManager::delete_config(&sc);
}

TEST(action_manager_configured_action, rejects_missing_parameter)
{
    SnortConfig sc;
    ActionManager::new_config(&sc);
    action_plugin = ActionManager::get_interface(&other_param_action_api);

    const IpsAction* action = ActionManager::instantiate_action_with_param(
        "test_action", "page", "page.html", &sc);

    CHECK(action == nullptr);
    CHECK_EQUAL(1, parse_errors);
    CHECK_EQUAL(1, module_ctor_calls);
    CHECK_EQUAL(1, module_dtor_calls);
    CHECK_EQUAL(0, action_ctor_calls);
    ActionManager::delete_config(&sc);
}

TEST(action_manager_configured_action, instantiates_action_with_parameter)
{
    SnortConfig sc;
    ActionManager::new_config(&sc);
    action_plugin = ActionManager::get_interface(&page_action_api);

    const IpsAction* action = ActionManager::instantiate_action_with_param(
        "test_action", "page", "page.html", &sc);

    CHECK(action != nullptr);
    CHECK_EQUAL(0, parse_errors);
    CHECK_EQUAL(1, module_ctor_calls);
    CHECK_EQUAL(1, module_dtor_calls);
    CHECK_EQUAL(1, action_ctor_calls);
    STRCMP_EQUAL("page.html", configured_page.c_str());
    ActionManager::delete_config(&sc);
    CHECK_EQUAL(1, action_dtor_calls);
}

TEST(action_manager_configured_action, instantiates_action_without_module_dtor)
{
    SnortConfig sc;
    ActionManager::new_config(&sc);
    action_plugin = ActionManager::get_interface(&page_action_without_module_dtor_api);

    const IpsAction* action = ActionManager::instantiate_action_with_param(
        "test_action", "page", "page.html", &sc);

    CHECK(action != nullptr);
    CHECK_EQUAL(0, parse_errors);
    CHECK_EQUAL(1, module_ctor_calls);
    CHECK_EQUAL(0, module_dtor_calls);
    CHECK_EQUAL(1, action_ctor_calls);
    STRCMP_EQUAL("page.html", configured_page.c_str());
    ActionManager::delete_config(&sc);
    CHECK_EQUAL(1, action_dtor_calls);
}

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
