#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../mp_unix_transport_module.h"

#include "framework/value.h"
#include "main/snort_config.h"
#include "main/snort.h"
#include "main/thread_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>


static int warning_cnt = 0;
static int destroy_cnt = 0;

namespace snort
{
    void WarningMessage(const char*,...) { warning_cnt++; }

    SnortConfig::SnortConfig(snort::SnortConfig const*, char const*)
    {
        max_procs = 2;
    }
    SnortConfig::~SnortConfig()
    {

    }

    unsigned ThreadConfig::get_instance_max()
    {
        return 1;
    }
    unsigned Snort::get_process_id()
    {
        return 1;
    }
    unsigned get_instance_id()
    {
        return 1;
    }

    MPUnixDomainTransport::MPUnixDomainTransport(MPUnixDomainTransportConfig* config, MPUnixTransportStats& stats) :
        MPTransport(), config(config), transport_stats(stats)
    { }
    MPUnixDomainTransport::~MPUnixDomainTransport()
    { destroy_cnt++; }
    void MPUnixDomainTransport::thread_init()
    {}
    void MPUnixDomainTransport::thread_term()
    {}
    void MPUnixDomainTransport::init_connection()
    {}
    void MPUnixDomainTransport::cleanup()
    {}
    void MPUnixDomainTransport::register_event_helpers(const unsigned&, const unsigned&, MPHelperFunctions&)
    {}
    bool MPUnixDomainTransport::send_to_transport(MPEventInfo&)
    { return true; }
    void MPUnixDomainTransport::unregister_receive_handler()
    { }
    void MPUnixDomainTransport::register_receive_handler(const TransportReceiveEventHandler&)
    {}
    bool MPUnixDomainTransport::configure(const SnortConfig*)
    { return true; }
    bool MPUnixDomainTransport::is_logging_enabled()
    { return false; }
    void MPUnixDomainTransport::enable_logging()
    {}
    void MPUnixDomainTransport::disable_logging()
    {}
    MPTransportChannelStatusHandle* MPUnixDomainTransport::get_channel_status(unsigned int& size)
    {
        size = 0;
        return nullptr;
    }
    void MPUnixDomainTransport::reset_stats()
    {
        transport_stats = MPUnixTransportStats();
    }
    void MPUnixDomainTransport::sum_stats()
    {
        
    }

    char* snort_strdup(const char*)
    {
        return nullptr;
    }
};

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }

using namespace snort;

MPUnixDomainTransportModule* mod = nullptr;

TEST_GROUP(MPUnixDomainTransportModuleTests)
{
    void setup() override
    {
        mod = (MPUnixDomainTransportModule*)mod_ctor();
    }

    void teardown() override
    {
        mod_dtor(mod);
    }
};

TEST(MPUnixDomainTransportModuleTests, MPUnixDomainTransportModuleConfigBegin)
{
    SnortConfig sc;
    auto res = mod->begin("test", 0, &sc);
    CHECK(res == true);
    CHECK(mod->config != nullptr);
}

TEST(MPUnixDomainTransportModuleTests, MPUnixDomainTransportModuleConfigEnd)
{
    auto res = mod->end("test", 0, nullptr);
    CHECK(res == true);
}

TEST(MPUnixDomainTransportModuleTests, MPUnixDomainTransportModuleConfigSet)
{
    Parameter p{"unix_domain_socket_path", Parameter::PT_STRING, nullptr, "test_value", nullptr};
    Parameter p2{"max_connect_retries", Parameter::PT_INT, nullptr, "15", nullptr};
    Parameter p3{"retry_interval_seconds", Parameter::PT_INT, nullptr, "33", nullptr};
    Parameter p4{"connect_timeout_seconds", Parameter::PT_INT, nullptr, "32", nullptr};
    Parameter p5{"consume_message_timeout_milliseconds", Parameter::PT_INT, nullptr, "200", nullptr};
    Parameter p6{"consume_message_batch_size", Parameter::PT_INT, nullptr, "20", nullptr};
    Parameter p7{"enable_logging", Parameter::PT_BOOL, nullptr, "true", nullptr};
    Value v("test_value");
    v.set(&p);

    SnortConfig sc;
    mod->begin("test", 0, &sc);
    auto res = mod->set(nullptr, v, nullptr);
    
    CHECK(res == true);
    CHECK(strcmp("test_value", mod->config->unix_domain_socket_path.c_str()) == 0);

    v.set((double)15);
    v.set(&p2);
    res = mod->set(nullptr, v, nullptr);
    CHECK(res == true);
    CHECK(mod->config->max_retries == 15);

    v.set((double)33);
    v.set(&p3);
    res = mod->set(nullptr, v, nullptr);
    CHECK(res == true);
    CHECK(mod->config->retry_interval_seconds == 33);

    v.set((double)32);
    v.set(&p4);
    res = mod->set(nullptr, v, nullptr);
    CHECK(res == true);
    CHECK(mod->config->connect_timeout_seconds == 32);

    v.set((double)200);
    v.set(&p5);
    res = mod->set(nullptr, v, nullptr);
    CHECK(res == true);
    CHECK(mod->config->consume_message_timeout_milliseconds == 200);

    v.set((double)20);
    v.set(&p6);
    res = mod->set(nullptr, v, nullptr);
    CHECK(res == true);
    CHECK(mod->config->consume_message_batch_size == 20);

    v.set(true);
    v.set(&p7);
    res = mod->set(nullptr, v, nullptr);
    CHECK(res == true);
    CHECK(mod->config->enable_logging == true);
}

TEST(MPUnixDomainTransportModuleTests, MPUnixDomainTransportModuleConfigUnknownSet)
{
    warning_cnt = 0;
    
    Parameter p{"unknown_value", Parameter::PT_STRING, nullptr, "/tmp/unx_dmn_sck", nullptr};
    Value v("/tmp/unx_dmn_sck");
    v.set(&p);

    SnortConfig sc;
    mod->begin("test", 0, &sc);
    auto res = mod->set(nullptr, v, nullptr);
    
    CHECK(res == false);
    CHECK(1 == warning_cnt);
}

TEST(MPUnixDomainTransportModuleTests, MPUnixDomainTransportModuleGetUsage)
{
    auto res = mod->get_usage();
    CHECK(res == Module::Usage::GLOBAL);
}

TEST(MPUnixDomainTransportModuleTests, MPUnixDomainTransportModuleCreateDestroyTransport)
{
    destroy_cnt = 0;
    auto transport = mp_unixdomain_transport_ctor(mod);
    CHECK(transport != nullptr);

    mp_unixdomain_transport_dtor(transport);
    CHECK(destroy_cnt == 1);
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}