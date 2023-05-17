//--------------------------------------------------------------------------
// Copyright (C) 2019-2023 Cisco and/or its affiliates. All rights reserved.
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
// data_bus_test.cc author Steven Baigal <sbaigal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/data_bus.h"
#include "main/snort_config.h"
#include "main/thread.h"
#include "utils/stats.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
#include <CppUTestExt/MockSupport.h>

using namespace snort;

//--------------------------------------------------------------------------
// mocks
//--------------------------------------------------------------------------
InspectionPolicy::InspectionPolicy(unsigned int) {}
InspectionPolicy::~InspectionPolicy() = default;
NetworkPolicy::NetworkPolicy(unsigned int, unsigned int) {}
NetworkPolicy::~NetworkPolicy() = default;
namespace snort
{

static SnortConfig s_conf;

THREAD_LOCAL SnortConfig* snort_conf = &s_conf;

const SnortConfig* SnortConfig::get_conf()
{ return snort_conf; }

SnortConfig::SnortConfig(const SnortConfig* const, const char*)
{ global_dbus = new DataBus(); }

SnortConfig::~SnortConfig()
{ delete global_dbus; }

NetworkPolicy* get_network_policy()
{
    NetworkPolicy* my_network_policy =
        (NetworkPolicy*)mock().getData("my_network_policy").getObjectPointer();
    return my_network_policy;
}

InspectionPolicy* get_inspection_policy()
{
    InspectionPolicy* my_inspection_policy =
        (InspectionPolicy*)mock().getData("my_inspection_policy").getObjectPointer();
    return my_inspection_policy;
}

THREAD_LOCAL PacketCount pc;
}

//--------------------------------------------------------------------------
class UTestEvent : public DataEvent
{
public:
    UTestEvent(int m) : msg(m) { }

    int get_message()
    { return msg; }

private:
    int msg;
};

class UTestHandler : public DataHandler
{
public:
    UTestHandler(unsigned u = 0) : DataHandler("unit_test")
    { if ( u ) order = u; }

    void handle(DataEvent&, Flow*) override;

    int evt_msg = 0;
    unsigned seq = 99;
};

static unsigned s_next = 0;

void UTestHandler::handle(DataEvent& event, Flow*)
{
    UTestEvent* evt = (UTestEvent*)&event;
    evt_msg = evt->get_message();
    seq = ++s_next;
}

struct DbUtIds { enum : unsigned { EVENT, num_ids }; };

const PubKey pub_key { "db_ut", DbUtIds::num_ids };

//--------------------------------------------------------------------------
// data bus unit tests
//--------------------------------------------------------------------------

static constexpr unsigned event_id = 1;

TEST_GROUP(data_bus)
{
    InspectionPolicy my_inspection_policy;
    NetworkPolicy my_network_policy;
    unsigned pub_id = 0;

    void setup() override
    {
        mock().setDataObject("my_network_policy", "NetworkPolicy", &my_network_policy);
        mock().setDataObject("my_inspection_policy", "InspectionPolicy", &my_inspection_policy);

        pub_id = DataBus::get_id(pub_key);
        CHECK_TRUE(DataBus::valid(pub_id));
    }

    void teardown() override
    {
        mock().clear();
    }
};

TEST(data_bus, subscribe_global)
{
    UTestHandler h;
    DataBus::subscribe_global(pub_key, DbUtIds::EVENT, &h, *snort_conf);

    UTestEvent event(100);
    DataBus::publish(pub_id, DbUtIds::EVENT, event);
    CHECK(100 == h.evt_msg);

    UTestEvent event1(200);
    DataBus::publish(pub_id, DbUtIds::EVENT, event1);
    CHECK(200 == h.evt_msg);

    DataBus::unsubscribe_global(pub_key, DbUtIds::EVENT, &h, *snort_conf);

    UTestEvent event2(300);
    DataBus::publish(pub_id, DbUtIds::EVENT, event2);
    CHECK(200 == h.evt_msg); // unsubscribed!
}

TEST(data_bus, subscribe_network)
{
    UTestHandler* h = new UTestHandler();
    DataBus::subscribe_network(pub_key, DbUtIds::EVENT, h);

    UTestEvent event(100);
    DataBus::publish(pub_id, DbUtIds::EVENT, event);
    CHECK(100 == h->evt_msg);

    UTestEvent event1(200);
    DataBus::publish(pub_id, DbUtIds::EVENT, event1);
    CHECK(200 == h->evt_msg);

    DataBus::unsubscribe_network(pub_key, DbUtIds::EVENT, h);

    UTestEvent event2(300);
    DataBus::publish(pub_id, DbUtIds::EVENT, event2);
    CHECK(200 == h->evt_msg); // unsubscribed!

    delete h;
}

TEST(data_bus, subscribe)
{
    UTestHandler* h = new UTestHandler();
    DataBus::subscribe(pub_key, DbUtIds::EVENT, h);

    UTestEvent event(100);
    DataBus::publish(pub_id, DbUtIds::EVENT, event);
    CHECK(100 == h->evt_msg);

    UTestEvent event1(200);
    DataBus::publish(pub_id, DbUtIds::EVENT, event1);
    CHECK(200 == h->evt_msg);

    DataBus::unsubscribe(pub_key, DbUtIds::EVENT, h);

    UTestEvent event2(300);
    DataBus::publish(pub_id, DbUtIds::EVENT, event2);
    CHECK(200 == h->evt_msg); // unsubscribed!

    delete h;
}

TEST(data_bus, order1)
{
    UTestHandler* h0 = new UTestHandler();
    DataBus::subscribe(pub_key, DbUtIds::EVENT, h0);

    UTestHandler* h1 = new UTestHandler(1);
    DataBus::subscribe(pub_key, DbUtIds::EVENT, h1);

    UTestHandler* h9 = new UTestHandler(9);
    DataBus::subscribe(pub_key, DbUtIds::EVENT, h9);

    s_next = 0;
    UTestEvent event(100);
    DataBus::publish(pub_id, DbUtIds::EVENT, event);

    CHECK(1 == h1->seq);
    CHECK(2 == h9->seq);
    CHECK(3 == h0->seq);

    DataBus::unsubscribe(pub_key, DbUtIds::EVENT, h0);
    DataBus::unsubscribe(pub_key, DbUtIds::EVENT, h1);
    DataBus::unsubscribe(pub_key, DbUtIds::EVENT, h9);

    delete h0;
    delete h1;
    delete h9;
}

TEST(data_bus, order2)
{
    UTestHandler* h0 = new UTestHandler(0);
    DataBus::subscribe(pub_key, DbUtIds::EVENT, h0);

    UTestHandler* h9 = new UTestHandler(9);
    DataBus::subscribe(pub_key, DbUtIds::EVENT, h9);

    UTestHandler* h1 = new UTestHandler(1);
    DataBus::subscribe(pub_key, DbUtIds::EVENT, h1);

    s_next = 0;
    UTestEvent event(100);
    DataBus::publish(pub_id, DbUtIds::EVENT, event);

    CHECK(1 == h1->seq);
    CHECK(2 == h9->seq);
    CHECK(3 == h0->seq);

    DataBus::unsubscribe(pub_key, DbUtIds::EVENT, h0);
    DataBus::unsubscribe(pub_key, DbUtIds::EVENT, h1);
    DataBus::unsubscribe(pub_key, DbUtIds::EVENT, h9);

    delete h0;
    delete h1;
    delete h9;
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

