#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/mp_data_bus.h"
#include "framework/mp_transport.h"
#include "framework/module.h"
#include "main/thread_config.h"
#include "managers/plug_interface.h"
#include "managers/plugin_manager.h"

#include "../mp_transport_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include <unordered_map>

#define MODULE_NAME "mock_transport"
#define MODULE_HELP "mock transport for testing"

static int test_transport_ctor_calls = 0;
static int test_transport_dtor_calls = 0;
static int test_transport_pinit_calls = 0;
static int test_transport_pterm_calls = 0;
static int test_transport_tinit_calls = 0;
static int test_transport_tterm_calls = 0;

namespace snort
{

class MockTransport : public MPTransport
{
    public:
    MockTransport() : MPTransport()
    { }
    virtual ~MockTransport() override
    { }
// LCOV_EXCL_START
    virtual bool send_to_transport(MPEventInfo& event) override
    { return true; }
    virtual void register_event_helpers(
        const unsigned& pub_id, const unsigned& event_id, MPHelperFunctions& helper) override
    { }
    virtual void init_connection() override
    { }
    virtual void register_receive_handler(const TransportReceiveEventHandler& handler) override
    { }
    virtual void unregister_receive_handler() override
    { }
    virtual void thread_init() override
    { }
    virtual void thread_term() override
    { }
    virtual bool configure(const SnortConfig*) override
    { return true; }
    virtual void enable_logging() override
    { }
    virtual void disable_logging() override
    { }
    virtual bool is_logging_enabled() override
    { return false; }
    MPTransportChannelStatusHandle* get_channel_status(unsigned int& size) override
    {
        size = 0;
        return nullptr;
    }
// LCOV_EXCL_STOP
};

// LCOV_EXCL_START
unsigned get_instance_id() { return 0; }
unsigned ThreadConfig::get_instance_max() { return 1; }
// LCOV_EXCL_STOP
};


using namespace snort;

// LCOV_EXCL_START
void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }
// LCOV_EXCL_STOP

static void mock_transport_tinit(MPTransport* t)
{
    test_transport_tinit_calls++;
}
static void mock_transport_tterm(MPTransport* t)
{
    test_transport_tterm_calls++;
}
static MPTransport* mock_transport_ctor(Module* m)
{   
    test_transport_ctor_calls++;
    return new MockTransport();
}
static void mock_transport_dtor(MPTransport* t)
{
    test_transport_dtor_calls++;
    delete t;
}

static void mock_transport_pinit()
{
    // Mock plugin init
    test_transport_pinit_calls++;
}
static void mock_transport_pterm()
{
    // Mock plugin term
    test_transport_pterm_calls++;
}

static void clear_test_calls()
{
    test_transport_ctor_calls = 0;
    test_transport_dtor_calls = 0;
    test_transport_pinit_calls = 0;
    test_transport_pterm_calls = 0;
    test_transport_tinit_calls = 0;
    test_transport_tterm_calls = 0;
}

static struct MPTransportApi mock_transport_api =
{
    {
        PT_MP_TRANSPORT,
        sizeof(MPTransportApi),
        MP_TRANSPORT_API_VERSION,
        2,
        API_RESERVED,
        API_OPTIONS,
        MODULE_NAME,
        MODULE_HELP,
        nullptr,
        nullptr
    },
    0,
    mock_transport_pinit,
    mock_transport_pterm,
    mock_transport_tinit,
    mock_transport_tterm,
    mock_transport_ctor,
    mock_transport_dtor
};

static PlugInterface* pin = nullptr;

PlugInterface* PluginManager::get_interface(const char* name)
{ return !strcmp(name, MODULE_NAME) ? pin : nullptr; }

unsigned PluginManager::for_each(PlugType pt, PlugFunc pf, void* pv)
{
    if ( !pin )
        return 0;

    pf(pin, pv);
    return 1;
}

TEST_GROUP(mp_transport_manager_test_group)
{
    void setup() override
    {
        clear_test_calls();
        pin = MPTransportManager::get_interface(&mock_transport_api);
        pin->instantiate(nullptr, nullptr, nullptr);
    }

    void teardown() override
    {
        MPTransportManager::term();
        delete pin;
    }
};

TEST(mp_transport_manager_test_group, instantiate_transport_object)
{
    CHECK(test_transport_ctor_calls == 1);
}

TEST(mp_transport_manager_test_group, get_transport_object)
{
    MPTransport* transport = MPTransportManager::get_transport(MODULE_NAME);
    CHECK(transport != nullptr);

    transport = MPTransportManager::get_transport("non_existent_transport");
    CHECK(transport == nullptr);
}

TEST(mp_transport_manager_test_group, add_plugin)
{
    pin->global_init();
    CHECK(test_transport_pinit_calls == 1);

    pin->global_term();
    CHECK(test_transport_pterm_calls == 1);
}

TEST(mp_transport_manager_test_group, thread_init_term)
{
    pin->thread_init();
    CHECK(test_transport_tinit_calls == 1);

    pin->thread_term();
    CHECK(test_transport_tterm_calls == 1);
}

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}

