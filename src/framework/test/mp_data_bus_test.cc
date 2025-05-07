//--------------------------------------------------------------------------
// Copyright (C) 2019-2025 Cisco and/or its affiliates. All rights reserved.
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
// mp_data_bus_test.cc author Umang Sharma <umasharm@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "../mp_data_bus.h"
#include "../main/snort_config.h"
#include "utils/stats.h"
#include "helpers/ring.h"
#include "main/snort.h"
#include "managers/module_manager.h"
#include <condition_variable>

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

#include <managers/mp_transport_manager.h>
#include <framework/mp_transport.h>

using namespace snort;

namespace snort
{
static SnortConfig s_conf;

THREAD_LOCAL SnortConfig* snort_conf = &s_conf;

void ErrorMessage(const char*, ...) { }
void LogMessage(const char*, ...) { }

const SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

SnortConfig::SnortConfig(const SnortConfig* const, const char*)
: daq_config(nullptr), thread_config(nullptr)
{ }

SnortConfig::~SnortConfig()
{ }

void set_log_conn(ControlConn*) { }

unsigned Snort::get_process_id()
{
    return 0;
}

Module* ModuleManager::get_module(const char*)
{
    return nullptr;
}
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) 
{
    mock().actualCall("show_stats");
}
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }
void show_stats(unsigned long*, PegInfo const*, char const*) {}

bool ControlConn::respond(const char*, ...) { return true; }

static bool test_transport_send_result = true;

class MockMPTransport : public MPTransport
{
public:
    MockMPTransport() = default;
    ~MockMPTransport() override = default;

    static int get_count()
    {
        return count;
    }

    static void reset_count()
    {
        count = 0;
    }

    static int get_test_register_helpers_calls()
    {
        return test_register_helpers_calls;
    }

    bool send_to_transport(MPEventInfo&) override
    {
        count++;
        return test_transport_send_result;
    }

    void register_event_helpers(const unsigned&, const unsigned&, MPHelperFunctions&) override
    {
        test_register_helpers_calls++;
        return;
    }

    void init_connection() override
    {
        return;
    }

    void register_receive_handler(const TransportReceiveEventHandler&) override
    {
        return;
    }

    void unregister_receive_handler() override
    {
        return;
    }

    void thread_init() override
    {
        return;
    }

    void thread_term() override
    {
        return;
    }

    bool configure(const SnortConfig*) override
    {
        return true;
    }

    void enable_logging() override
    {
        return;
    }

    void disable_logging() override
    {
        return;
    }

    bool is_logging_enabled() override
    {
        return true;
    }

    MPTransportChannelStatusHandle* get_channel_status(unsigned int& size) override
    {
        size = 0;
        return nullptr;
    }

private:
    inline static int count = 0;
    inline static int test_register_helpers_calls = 0;
};

static MockMPTransport mp_transport_pointer;

MPTransport* MPTransportManager::get_transport(const std::string&)
{
    return &mp_transport_pointer;
}

class UTestEvent : public DataEvent
{
public:
    UTestEvent(int m) : msg(m) { }

    int get_message() const
    { return msg; }

private:
    int msg;
};

bool serialize_mock(DataEvent*, char*& buffer, uint16_t* length)
{
    buffer = new char[9];
    *length = 9;
    memcpy(buffer, "test_data", 9);
    return true;
}

bool deserialize_mock(const char*, uint16_t length, DataEvent*& event)
{
    event = new UTestEvent(length);
    return true;
}

class UTestHandler1 : public DataHandler
{
public:
    UTestHandler1(unsigned u = 0) : DataHandler("unit_test1")
    { if (u) order = u; }

    void handle(DataEvent& event, Flow*) override;

    int evt_msg = 0;
};

class UTestHandler2 : public DataHandler
{
public:
    UTestHandler2(unsigned u = 0) : DataHandler("unit_test2")
    { if (u) order = u; }

    void handle(DataEvent& event, Flow*) override;

    int evt_msg = 1;
};

void UTestHandler1::handle(DataEvent& event, Flow*)
{
    UTestEvent* evt = static_cast<UTestEvent*>(&event);
    if (evt)
    {
        evt_msg = evt->get_message();
    }
}

void UTestHandler2::handle(DataEvent& event, Flow*)
{
    UTestEvent* evt = static_cast<UTestEvent*>(&event);
    if (evt)
    {
        evt_msg = evt->get_message();
    }
}
//--------------------------------------------------------------------------


struct DbUtIds { enum : unsigned { EVENT1, EVENT2, num_ids }; };

const PubKey pub_key1 { "mp_ut1", DbUtIds::num_ids };
const PubKey pub_key2 { "mp_ut2", DbUtIds::num_ids };

//--------------------------------------------------------------------------
// Test Group
//--------------------------------------------------------------------------

TEST_GROUP(mp_data_bus_pub)
{
    unsigned pub_id1 = 0;  // cppcheck-suppress variableScope
    MPDataBus* mp_dbus = nullptr;
    void setup() override
    {
        MockMPTransport::reset_count();
        mp_dbus = new MPDataBus();
        mp_dbus->init(2);
        pub_id1 = MPDataBus::get_id(pub_key1);
        CHECK(MPDataBus::valid(pub_id1));

        snort_conf->mp_dbus = mp_dbus;
    }

    void teardown() override
    { }
};

TEST(mp_data_bus_pub, publish)
{
    CHECK_TRUE(mp_dbus->get_event_queue()->empty());
    CHECK_TRUE(mp_dbus->get_event_queue()->count() == 0);

    std::shared_ptr<UTestEvent> event = std::make_shared<UTestEvent>(100);

    mp_dbus->publish(pub_id1, DbUtIds::EVENT1, event);

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    mp_dbus->sum_stats();
    CHECK_EQUAL(1, MPDataBus::mp_global_stats.total_messages_published);
    CHECK_EQUAL(1, MPDataBus::mp_global_stats.total_messages_sent);
    CHECK_EQUAL(0, MPDataBus::mp_global_stats.total_messages_dropped);

    mock().expectNCalls(2, "show_stats");

    mp_dbus->dump_stats(nullptr, nullptr);
    mp_dbus->dump_stats(nullptr, "mp_ut1");

    mock().checkExpectations();

    delete mp_dbus;

    CHECK_EQUAL(1, MockMPTransport::get_count());
}

TEST(mp_data_bus_pub, publish_fail_to_send)
{
    CHECK_TRUE(mp_dbus->get_event_queue()->empty());
    CHECK_TRUE(mp_dbus->get_event_queue()->count() == 0);

    test_transport_send_result = false;

    std::shared_ptr<UTestEvent> event = std::make_shared<UTestEvent>(100);

    mp_dbus->publish(pub_id1, DbUtIds::EVENT1, event);

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    mp_dbus->sum_stats();
    CHECK_EQUAL(1, MPDataBus::mp_global_stats.total_messages_published);
    CHECK_EQUAL(0, MPDataBus::mp_global_stats.total_messages_sent);
    CHECK_EQUAL(1, MPDataBus::mp_global_stats.total_messages_dropped);

    delete mp_dbus;

    test_transport_send_result = true;
}

TEST_GROUP(mp_data_bus)
{
    unsigned pub_id1 = 0, pub_id2 = 0;  // cppcheck-suppress variableScope

    void setup() override
    {
        unsigned max_procs_val = 2;
        snort_conf->mp_dbus = new MPDataBus();
        snort_conf->mp_dbus->init(max_procs_val);
        pub_id1 = MPDataBus::get_id(pub_key1);
        pub_id2 = MPDataBus::get_id(pub_key2);
        CHECK(MPDataBus::valid(pub_id1));
        CHECK(MPDataBus::valid(pub_id2));
    }

    void teardown() override
    {
        delete snort_conf->mp_dbus;
    }
};

//--------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------

TEST(mp_data_bus, init)
{
    CHECK(SnortConfig::get_conf()->mp_dbus != nullptr);  
    CHECK(SnortConfig::get_conf()->mp_dbus->get_event_queue() != nullptr);
}

TEST(mp_data_bus, no_subscribers_and_receive)
{
    UTestHandler1* h1 = new UTestHandler1();

    std::shared_ptr<UTestEvent> event1 = std::make_shared<UTestEvent>(100);

    MPEventInfo event_info1(event1, MPEventType(DbUtIds::EVENT1), pub_id1);
    SnortConfig::get_conf()->mp_dbus->receive_message(event_info1);

    CHECK_EQUAL(0, h1->evt_msg);
    delete h1;
    h1 = nullptr;
}

TEST(mp_data_bus, register_event_helpers)
{
    MPSerializeFunc serialize_func = serialize_mock;
    MPDeserializeFunc deserialize_func = deserialize_mock;
    CHECK(0 == MockMPTransport::get_test_register_helpers_calls());

    MPDataBus::register_event_helpers(pub_key1, DbUtIds::EVENT1, serialize_func, deserialize_func);
    CHECK(1 == MockMPTransport::get_test_register_helpers_calls());

    MPDataBus::register_event_helpers(pub_key1, DbUtIds::EVENT1, serialize_func, deserialize_func);
    CHECK(2 == MockMPTransport::get_test_register_helpers_calls());
}

TEST(mp_data_bus, subscribe_and_receive)
{
    // one snort subscribes to it
    UTestHandler1* h1 = new UTestHandler1();
    MPDataBus::subscribe(pub_key1, DbUtIds::EVENT1, h1);

    // publish event from other snort
    // since we don't have a way to publish events, we will use receive_message to simulate the event
    // from a different snort
    std::shared_ptr<UTestEvent> event = std::make_shared<UTestEvent>(100);

    MPEventInfo event_info(event, MPEventType(DbUtIds::EVENT1), pub_id1);
    SnortConfig::get_conf()->mp_dbus->receive_message(event_info);
    
    CHECK_EQUAL(100, h1->evt_msg);

    std::shared_ptr<UTestEvent> event1 = std::make_shared<UTestEvent>(200);
    
    MPEventInfo event_info1(event1, MPEventType(DbUtIds::EVENT1), pub_id1);
    SnortConfig::get_conf()->mp_dbus->receive_message(event_info1);
    
    SnortConfig::get_conf()->mp_dbus->sum_stats();
    CHECK_EQUAL(2, MPDataBus::mp_global_stats.total_messages_received);

    CHECK_EQUAL(200, h1->evt_msg);
}

TEST(mp_data_bus, two_subscribers_diff_event_and_receive)
{
    UTestHandler1* h1 = new UTestHandler1();
    UTestHandler2* h2 = new UTestHandler2();

    MPDataBus::subscribe(pub_key1, DbUtIds::EVENT1, h1);
    MPDataBus::subscribe(pub_key2, DbUtIds::EVENT2, h2);

    std::shared_ptr<UTestEvent> event1 = std::make_shared<UTestEvent>(100);

    MPEventInfo event_info1(event1, MPEventType(DbUtIds::EVENT1), pub_id1);
    SnortConfig::get_conf()->mp_dbus->receive_message(event_info1);

    CHECK_EQUAL(100, h1->evt_msg);
    CHECK_EQUAL(1, h2->evt_msg);

    std::shared_ptr<UTestEvent> event2 = std::make_shared<UTestEvent>(200);

    MPEventInfo event_info2(event2, MPEventType(DbUtIds::EVENT2), pub_id2);
    SnortConfig::get_conf()->mp_dbus->receive_message(event_info2);

    CHECK_EQUAL(100, h1->evt_msg);
    CHECK_EQUAL(200, h2->evt_msg);
}

TEST(mp_data_bus, two_subscribers_same_event_and_receive)
{
    UTestHandler1* h1 = new UTestHandler1();
    UTestHandler2* h2 = new UTestHandler2();

    MPDataBus::subscribe(pub_key1, DbUtIds::EVENT1, h1);
    MPDataBus::subscribe(pub_key2, DbUtIds::EVENT1, h2);

    std::shared_ptr<UTestEvent> event1 = std::make_shared<UTestEvent>(100);

    MPEventInfo event_info1(event1, MPEventType(DbUtIds::EVENT1), pub_id1);
    SnortConfig::get_conf()->mp_dbus->receive_message(event_info1);

    CHECK_EQUAL(100, h1->evt_msg);
    CHECK_EQUAL(1, h2->evt_msg);
}

TEST_GROUP(mp_data_bus_clone)
{
    unsigned pub_id1 = 0, pub_id2 = 0;  // cppcheck-suppress variableScope
    void setup() override
    {
        unsigned max_procs_val = 2;
        snort_conf->mp_dbus = new MPDataBus();
        snort_conf->mp_dbus->init(max_procs_val);
        pub_id1 = MPDataBus::get_id(pub_key1);
        pub_id2 = MPDataBus::get_id(pub_key2);
        CHECK(MPDataBus::valid(pub_id1));
        CHECK(MPDataBus::valid(pub_id2));
    }

    void teardown() override
    {
        delete snort_conf->mp_dbus;
    }
};
//-------------------------------------------------------------------------

TEST(mp_data_bus_clone, z_clone)
{
    unsigned pub_id1, pub_id2;
    pub_id1 = MPDataBus::get_id(pub_key1);
    pub_id2 = MPDataBus::get_id(pub_key2);
    // subscribing to the events in the original mp_data_bus
    // and then cloning the mp_data_bus
    // and checking if the events are received in the cloned mp_data_bus
    // and not in the original mp_data_bus
    UTestHandler1* h1 = new UTestHandler1();
    MPDataBus::subscribe(pub_key1, DbUtIds::EVENT1, h1);

    UTestHandler2* h2 = new UTestHandler2();
    MPDataBus::subscribe(pub_key2, DbUtIds::EVENT2, h2);

    // original mp_data_bus should be deleted with previous SnortConfig
    // deleted with exit handlers of Test framework
    MPDataBus* mp_data_bus_cloned = new MPDataBus();
    mp_data_bus_cloned->clone(*SnortConfig::get_conf()->mp_dbus, nullptr);

    std::shared_ptr<UTestEvent> event1 = std::make_shared<UTestEvent>(100);
    MPEventInfo event_info1(event1, MPEventType(DbUtIds::EVENT1), pub_id1);

    mp_data_bus_cloned->receive_message(event_info1);

    CHECK_EQUAL(100, h1->evt_msg);
    CHECK_EQUAL(1, h2->evt_msg);

    std::shared_ptr<UTestEvent> event2 = std::make_shared<UTestEvent>(200);

    MPEventInfo event_info2(event2, MPEventType(DbUtIds::EVENT2), pub_id2);
    mp_data_bus_cloned->receive_message(event_info2);
    CHECK_EQUAL(100, h1->evt_msg);
    CHECK_EQUAL(200, h2->evt_msg);
}

//-------------------------------------------------------------------------
// main
//-------------------------------------------------------------------------

int main(int argc, char** argv)
{
    // event_map is not released until after cpputest gives up
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    return CommandLineTestRunner::RunAllTests(argc, argv);
}