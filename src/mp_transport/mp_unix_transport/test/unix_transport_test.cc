#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/mp_transport.h"
#include "../mp_unix_transport.h"
#include "framework/counts.h"
#include "framework/mp_data_bus.h"
#include "main/snort.h"
#include "main/thread_config.h"
#include "main/snort_config.h"
#include "connectors/unixdomain_connector/unixdomain_connector.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include <mutex>
#include <condition_variable>
#include <vector>
#include <iostream>

static int snort_instance_id = 0;

static int accept_cnt = 0;

static int test_socket_calls = 0;
static int test_bind_calls = 0;
static int test_listen_calls = 0;
static int test_accept_calls = 0;
static int test_close_calls = 0;
static int test_connect_calls = 0;
static int test_call_sock_created = 0;
static int test_serialize_calls = 0;
static int test_deserialize_calls = 0;

int accept (int, struct sockaddr*, socklen_t*)
{
    test_accept_calls++;
    return accept_cnt--;
}

int close (int)
{ 
    test_close_calls++;
    return 0;
}

void clear_test_calls()
{
    test_socket_calls = 0;
    test_bind_calls = 0;
    test_listen_calls = 0;
    test_accept_calls = 0;
    test_close_calls = 0;
    test_connect_calls = 0;
    test_call_sock_created = 0;
    test_serialize_calls = 0;
    test_deserialize_calls = 0;
}

namespace snort
{
    void ErrorMessage(const char*,...) { }
    void WarningMessage(const char*,...) { }
    void LogMessage(const char* s, ...) { }
    void LogText(const char*, FILE*) {}
    void ParseError(const char*, ...) { }

    unsigned ThreadConfig::get_instance_max()
    {
        return 2; // Mock value for testing
    }

    SnortConfig::SnortConfig(snort::SnortConfig const*, char const*)
    {
        max_procs = 2;
    }
    SnortConfig::~SnortConfig()
    {

    }
    
    unsigned Snort::get_process_id()
    {
        return snort_instance_id;
    }

    unsigned get_instance_id()
    {
        return snort_instance_id;
    }
};
static int test_send_calls = 0;
UnixDomainConnector* listen_connector = nullptr;
UnixDomainConnector* call_connector = nullptr;

void UnixDomainConnector::set_message_received_handler(std::function<void ()> h)
{
    message_received_handler = h;
}

static bool expect_update_change = false;
std::function<void (UnixDomainConnector*,bool)> test_update_handler = nullptr;

void UnixDomainConnector::set_update_handler(std::function<void (UnixDomainConnector*,bool)> h)
{
    if(expect_update_change)
        test_update_handler = h;
}

void UnixDomainConnector::start_receive_thread()
{

}

static snort::ConnectorMsg* test_msg_answer = nullptr;
static snort::ConnectorMsg* test_msg_call = nullptr;
static uint8_t* test_msg_call_data = nullptr;
static uint8_t* test_msg_answer_data = nullptr;
UnixDomainConnectorListener::UnixDomainConnectorListener(char const*) // cppcheck-suppress uninitMemberVar
{}
UnixDomainConnectorListener::~UnixDomainConnectorListener()
{
}
void UnixDomainConnectorListener::stop_accepting_connections()
{
    close(0);
}
void UnixDomainConnectorListener::start_accepting_connections(UnixDomainConnectorAcceptHandler h, UnixDomainConnectorConfig* cfg)
{
    socket(0,0,0);
    while(accept_cnt > 0)
    {
        accept(0, nullptr, nullptr);
        auto cfg_copy = new UnixDomainConnectorConfig(*cfg);
        h(new UnixDomainConnector(*cfg_copy, 0, 0), cfg_copy);
    }
}

bool UnixDomainConnector::transmit_message(const snort::ConnectorMsg& m, const ID&)
{
    test_send_calls++;
    
    if (cfg.setup == UnixDomainConnectorConfig::Setup::CALL)
    {
        test_msg_call_data = new uint8_t[m.get_length()];
        memcpy(test_msg_call_data, m.get_data(), m.get_length());
        test_msg_call = new snort::ConnectorMsg(test_msg_call_data, m.get_length());
        if(!call_connector)
            call_connector = this;
        listen_connector->process_receive();
    }
    else
    {
        test_msg_answer_data = new uint8_t[m.get_length()];
        memcpy(test_msg_answer_data, m.get_data(), m.get_length());
        test_msg_answer = new snort::ConnectorMsg(test_msg_answer_data, m.get_length());
        if(!listen_connector)
            listen_connector = this;
        call_connector->process_receive();
    }
    
    return true;
}
void UnixDomainConnector::process_receive()
{
    if (message_received_handler)
    {
        message_received_handler();
    }
}
bool UnixDomainConnector::transmit_message(const snort::ConnectorMsg&&, const ID&)
{ return true; }
snort::ConnectorMsg UnixDomainConnector::receive_message(bool)
{
    if (cfg.setup == UnixDomainConnectorConfig::Setup::CALL)
    {
        if (test_msg_answer)
        {
            snort::ConnectorMsg msg(test_msg_answer_data, test_msg_answer->get_length());
            delete test_msg_answer;
            test_msg_answer = nullptr;
            return std::move(msg); // cppcheck-suppress returnStdMoveLocal
        }
    }
    else
    {
        if (test_msg_call)
        {
            snort::ConnectorMsg msg(test_msg_call_data, test_msg_call->get_length());
            delete test_msg_call;
            test_msg_call = nullptr;
            return std::move(msg); // cppcheck-suppress returnStdMoveLocal
        }
    }
    return snort::ConnectorMsg();
}
UnixDomainConnector::UnixDomainConnector(const UnixDomainConnectorConfig& config, int sfd, size_t idx, UnixDomainConnectorReconnectHelper*) : Connector(config) // cppcheck-suppress uninitMemberVar
{ cfg  = config; } // cppcheck-suppress useInitializationList
UnixDomainConnector::~UnixDomainConnector()
{
    close(0);
}

UnixDomainConnectorReconnectHelper::~UnixDomainConnectorReconnectHelper()
{}

void UnixDomainConnectorReconnectHelper::connect(const char* path, size_t idx)
{
    unixdomain_connector_tinit_call(cfg, path, idx, update_handler);
}

void UnixDomainConnectorReconnectHelper::reconnect(size_t idx)
{}

void UnixDomainConnectorReconnectHelper::set_reconnect_enabled(bool enabled)
{
    reconnect_enabled.store(enabled);
}

UnixDomainConnector* unixdomain_connector_tinit_call(const UnixDomainConnectorConfig& cfg, const char* path, size_t idx, const UnixDomainConnectorUpdateHandler& update_handler)
{
    if(cfg.setup == UnixDomainConnectorConfig::Setup::CALL)
    {
        test_call_sock_created++;
        auto new_conn = new UnixDomainConnector(cfg, 0, idx);
        call_connector = new_conn;
        update_handler(new_conn, false);
        return new_conn;
    }
    assert(false);
    return nullptr;
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }

using namespace snort;


static int s_socket_return = 1;
static int s_bind_return = 0;
static int s_listen_return = 0;
static int s_connect_return = 1;

#ifdef __GLIBC__
int socket (int, int, int) __THROW { test_socket_calls++; return s_socket_return; }
int bind (int, const struct sockaddr*, socklen_t) __THROW { test_bind_calls++; return s_bind_return; }
int listen (int, int) __THROW { test_listen_calls++; return s_listen_return; }
int unlink (const char *__name) __THROW { return 0;};
#else
int socket (int, int, int) { test_socket_calls++; return s_socket_return; }
int bind (int, const struct sockaddr*, socklen_t) { test_bind_calls++; return s_bind_return; }
int listen (int, int) { test_listen_calls++; return s_listen_return; }
int unlink (const char *__name) { return 0;};
#endif

int connect (int, const struct sockaddr*, socklen_t) { test_connect_calls++; return s_connect_return; }

int fcntl (int __fd, int __cmd, ...) { return 0;}
ssize_t send (int, const void*, size_t n, int) { return n; }


std::mutex accept_mutex;
std::condition_variable accept_cond;


class TestDataEvent : public DataEvent
{
public:
    TestDataEvent() {}
    ~TestDataEvent() override {}
};

bool serialize_mock(DataEvent* event, char*& buffer, uint16_t* length)
{
    test_serialize_calls++;
    buffer = new char[9];
    *length = 9;
    memcpy(buffer, "test_data", 9);
    return true;
}

bool deserialize_mock(const char* buffer, uint16_t length, DataEvent*& event)
{
    test_deserialize_calls++;
    event = new TestDataEvent();
    return true;
}

MPHelperFunctions mp_helper_functions_mock(serialize_mock, deserialize_mock);

static MPUnixDomainTransportConfig test_config;
static MPUnixTransportStats test_stats;
static MPUnixDomainTransport* test_transport = nullptr;

static SnortConfig test_snort_config(nullptr, nullptr);

TEST_GROUP(unix_transport_test_connectivity_group)
{
    void setup() override
    {
        test_snort_config.max_procs = 2;
        test_transport = new MPUnixDomainTransport(&test_config, test_stats);
        test_transport->configure(&test_snort_config);
    }

    void teardown() override
    {
        delete test_transport;
        test_transport = nullptr;
    }
};

static MPUnixDomainTransportConfig test_config_message;

static MPTransport* test_transport_message_1 = nullptr;
static MPTransport* test_transport_message_2 = nullptr;

static int received_1_msg_cnt = 0;
static int received_2_msg_cnt = 0;

TEST_GROUP(unix_transport_test_messaging)
{
    void setup() override
    {
        test_snort_config.max_procs = 2;

        accept_cnt = 1;

        test_config_message.unix_domain_socket_path = ".";
        test_config_message.max_processes = 2;
        test_config_message.conn_retries = false;
        test_config_message.retry_interval_seconds = 0;
        test_config_message.max_retries = 0;
        test_config_message.connect_timeout_seconds = 30;

        test_transport_message_1 = new MPUnixDomainTransport(&test_config_message, test_stats);
        snort_instance_id = 1;
        test_transport_message_1->configure(&test_snort_config);
        test_transport_message_1->init_connection();
        test_transport_message_1->register_receive_handler([](const snort::MPEventInfo& e)
        {
            received_1_msg_cnt++;
        });
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        test_transport_message_2 = new MPUnixDomainTransport(&test_config_message, test_stats);
        snort_instance_id = 2;
        test_transport_message_2->configure(&test_snort_config);
        test_transport_message_2->init_connection();
        test_transport_message_2->register_receive_handler([](const snort::MPEventInfo& e)
        {
            received_2_msg_cnt++;
        });
    }

    void teardown() override
    {
        delete test_transport_message_1;
        test_transport_message_1 = nullptr;
        delete test_transport_message_2;
        test_transport_message_2 = nullptr;
        delete[] test_msg_call_data;
        test_msg_call_data = nullptr;
        delete[] test_msg_answer_data;
        test_msg_answer_data = nullptr;
    }
};

TEST(unix_transport_test_connectivity_group, get_config)
{
    auto unix_transport = (MPUnixDomainTransport*)test_transport;
    CHECK(unix_transport->get_config() == &test_config);
};

TEST(unix_transport_test_connectivity_group, set_logging_enabled_disabled)
{
    auto logging_status = test_transport->is_logging_enabled();
    CHECK(logging_status == false);

    test_transport->enable_logging();
    logging_status = test_transport->is_logging_enabled();
    CHECK(logging_status == true);

    test_transport->disable_logging();
    logging_status = test_transport->is_logging_enabled();
    CHECK(logging_status == false);
};

TEST(unix_transport_test_connectivity_group, init_connection_single_snort_instance)
{
    clear_test_calls();
    test_config.unix_domain_socket_path = ".";
    test_config.max_processes = 1;

    test_transport->init_connection();
    
    CHECK(test_socket_calls == 0);
    CHECK(test_bind_calls == 0);
    CHECK(test_listen_calls == 0);
    CHECK(test_accept_calls == 0);
    CHECK(test_close_calls == 0);

    test_transport->cleanup();
    CHECK(test_close_calls == 0);
};

TEST(unix_transport_test_connectivity_group, init_connection_first_snort_instance)
{
    clear_test_calls();
    snort_instance_id = 1;

    test_config.unix_domain_socket_path = ".";
    test_config.max_processes = 2;

    accept_cnt = 1;

    test_transport->init_connection();

    CHECK(test_accept_calls == 1);

    test_transport->cleanup();
    CHECK(test_close_calls == 2);
};

TEST(unix_transport_test_connectivity_group, init_connection_second_snort_instance)
{
    clear_test_calls();
    snort_instance_id = 2;
    test_config.unix_domain_socket_path = ".";
    test_config.max_processes = 2;

    test_transport->init_connection();
    
    CHECK(test_bind_calls == 0);
    CHECK(test_listen_calls == 0);
    CHECK(test_accept_calls == 0);
    CHECK(test_close_calls == 0);
    CHECK(test_call_sock_created == 1);

    test_transport->cleanup();
    CHECK(test_close_calls == 1);
};

TEST(unix_transport_test_connectivity_group, connector_update_handler_call)
{
    clear_test_calls();
    
    test_config.unix_domain_socket_path = ".";
    test_config.max_processes = 2;

    accept_cnt = 1;
    snort_instance_id = 1;

    test_update_handler = nullptr;
    expect_update_change = true;

    test_transport->init_connection();

    CHECK(test_update_handler != nullptr);

    test_update_handler(nullptr, false);

    CHECK(test_close_calls == 1);
    expect_update_change = false;
    test_update_handler = nullptr;
};

static TestDataEvent test_event;

TEST(unix_transport_test_messaging, send_to_transport_biderectional)
{
    clear_test_calls();

    test_transport_message_1->register_event_helpers(0, 0, mp_helper_functions_mock);
    test_transport_message_2->register_event_helpers(0, 0, mp_helper_functions_mock);

    std::shared_ptr<TestDataEvent> event = std::make_shared<TestDataEvent>();

    MPEventInfo event_info(event, 0, 0);
    auto res = test_transport_message_1->send_to_transport(event_info);
    

    CHECK(res == true);
    CHECK(test_serialize_calls == 1);

    res = test_transport_message_2->send_to_transport(event_info);
    
    CHECK(res == true);
    CHECK(test_serialize_calls == 2);

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    CHECK_EQUAL(2, test_deserialize_calls);
    CHECK_EQUAL(1 ,received_1_msg_cnt);
    CHECK_EQUAL(1, received_2_msg_cnt);
    CHECK_EQUAL(2, test_send_calls);
};

TEST(unix_transport_test_messaging, send_to_transport_no_helpers)
{
    clear_test_calls();

    std::shared_ptr<TestDataEvent> event_in = std::make_shared<TestDataEvent>();

    MPEventInfo event(event_in, 0, 0);

    auto res = test_transport_message_1->send_to_transport(event);
    CHECK(res == false);
    CHECK(test_serialize_calls == 0);
    CHECK(test_deserialize_calls == 0);
    CHECK(received_1_msg_cnt == 0);
    CHECK(received_2_msg_cnt == 0);
    CHECK(test_send_calls == 0);

    res = test_transport_message_2->send_to_transport(event);
    CHECK(res == false);
    CHECK(test_serialize_calls == 0);
    CHECK(test_deserialize_calls == 0);
    CHECK(received_1_msg_cnt == 0);
    CHECK(received_2_msg_cnt == 0);
    CHECK(test_send_calls == 0);
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}