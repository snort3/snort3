//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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

// side_channel_test.cc author Ed Borgoyn <eborgoyn@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "side_channel/side_channel.h"

#include "log/messages.h"
#include "main/snort_debug.h"
#include "managers/connector_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

class TestConnectorMsgHandle : public ConnectorMsgHandle
{
public:
    TestConnectorMsgHandle(const uint32_t length)
    {
        connector_msg.length = length;
        connector_msg.data = new uint8_t[length];
    }

    ~TestConnectorMsgHandle()
    {
        delete[] connector_msg.data;
    }

    ConnectorMsg connector_msg;
};

class DuplexConnector : public Connector
{
    ConnectorMsgHandle* alloc_message(const uint32_t length, const uint8_t** data) override
    {
        TestConnectorMsgHandle* msg = new TestConnectorMsgHandle(length);
        *data = (uint8_t*)msg->connector_msg.data;
        return msg;
    }
    void discard_message(ConnectorMsgHandle* msg) override
    { delete (TestConnectorMsgHandle*)msg; }
    bool transmit_message(ConnectorMsgHandle* msg) override
    { delete (TestConnectorMsgHandle*)msg; return true; }
    ConnectorMsgHandle* receive_message(bool) override
    { return new TestConnectorMsgHandle(30); }
    ConnectorMsg* get_connector_msg(ConnectorMsgHandle* handle) override
    { return &((TestConnectorMsgHandle*)handle)->connector_msg; }
    Direction get_connector_direction() override
    { return CONN_DUPLEX; }
};

class ReceiveConnector : public Connector
{
    ConnectorMsgHandle* alloc_message(const uint32_t length, const uint8_t** data) override
    {
        TestConnectorMsgHandle* msg = new TestConnectorMsgHandle(length);
        *data = (uint8_t*)msg->connector_msg.data;
        return msg;
    }
    void discard_message(ConnectorMsgHandle* msg) override
    { delete (TestConnectorMsgHandle*)msg; }
    bool transmit_message(ConnectorMsgHandle* msg) override
    { delete (TestConnectorMsgHandle*)msg; return true; }
    ConnectorMsgHandle* receive_message(bool) override
    { return new TestConnectorMsgHandle(30); }
    ConnectorMsg* get_connector_msg(ConnectorMsgHandle* handle) override
    { return &((TestConnectorMsgHandle*)handle)->connector_msg; }
    Direction get_connector_direction() override
    { return CONN_RECEIVE; }
};

class TransmitConnector : public Connector
{
    ConnectorMsgHandle* alloc_message(const uint32_t length, const uint8_t** data) override
    {
        TestConnectorMsgHandle* msg = new TestConnectorMsgHandle(length);
        *data = (uint8_t*)msg->connector_msg.data;
        return msg;
    }
    void discard_message(ConnectorMsgHandle* msg) override
    { delete (TestConnectorMsgHandle*)msg; }
    bool transmit_message(ConnectorMsgHandle* msg) override
    { delete (TestConnectorMsgHandle*)msg; return true; }
    ConnectorMsgHandle* receive_message(bool) override
    { return nullptr; }
    ConnectorMsg* get_connector_msg(ConnectorMsgHandle*) override
    { return nullptr; }
    Direction get_connector_direction() override
    { return CONN_TRANSMIT; }
};

Connector* receive_connector = nullptr;
Connector* transmit_connector = nullptr;
Connector* duplex_connector = nullptr;

void ConnectorManager::thread_init()
{
    receive_connector = new ReceiveConnector;
    transmit_connector = new TransmitConnector;
    duplex_connector = new DuplexConnector;
}

void ConnectorManager::thread_term()
{
    delete receive_connector;
    delete transmit_connector;
    delete duplex_connector;
}

Connector* ConnectorManager::get_connector(const std::string& connector_name)
{
    if ( connector_name == "R" )
        return receive_connector;
    else if ( connector_name == "T" )
        return transmit_connector;
    else if ( connector_name == "D" )
        return duplex_connector;
    else
        return nullptr;
}

void ParseWarning(WarningGroup, const char*, ...) { }

TEST_GROUP(side_channel)
{
    void setup() override
    {
        // FIXIT-L workaround for issue with CppUTest memory leak detection
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        SideChannelManager::pre_config_init();

        SCConnectors test_connectors;
        PortBitSet test_ports;

        test_connectors.push_back("R");
        test_connectors.push_back("T");
        test_ports.set(1);

        SideChannelManager::instantiate(&test_connectors, &test_ports);

        test_connectors.clear();
        test_ports.reset(1);

        test_connectors.push_back("R");
        test_ports.set(2);

        SideChannelManager::instantiate(&test_connectors, &test_ports);

        test_connectors.clear();
        test_ports.reset(2);

        test_connectors.push_back("T");
        test_ports.set(3);

        SideChannelManager::instantiate(&test_connectors, &test_ports);

        test_connectors.clear();
        test_ports.reset(3);

        test_ports.set(4);

        SideChannelManager::instantiate(&test_connectors, &test_ports);

        test_connectors.clear();
        test_ports.reset(4);

        test_connectors.push_back("D");
        test_ports.set(5);

        SideChannelManager::instantiate(&test_connectors, &test_ports);

        test_connectors.clear();
        test_ports.reset(5);

        SideChannelManager::thread_init();
    }

    void teardown() override
    {
        SideChannelManager::thread_term();
        SideChannelManager::term();
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(side_channel, test_connector_null)
{
}

TEST(side_channel, test_connector_get_none)
{
    SideChannel* sc = SideChannelManager::get_side_channel(6);
    CHECK(sc == nullptr);
}

TEST(side_channel, test_connector_directions)
{
    SideChannel* sc = SideChannelManager::get_side_channel(1);
    CHECK(sc != nullptr);
    CHECK(sc->get_direction() == Connector::CONN_DUPLEX);

    sc = SideChannelManager::get_side_channel(2);
    CHECK(sc != nullptr);
    CHECK(sc->get_direction() == Connector::CONN_RECEIVE);

    sc = SideChannelManager::get_side_channel(3);
    CHECK(sc != nullptr);
    CHECK(sc->get_direction() == Connector::CONN_TRANSMIT);

    sc = SideChannelManager::get_side_channel(4);
    CHECK(sc != nullptr);
    CHECK(sc->get_direction() == Connector::CONN_UNDEFINED);

    sc = SideChannelManager::get_side_channel(5);
    CHECK(sc != nullptr);
    CHECK(sc->get_direction() == Connector::CONN_DUPLEX);
}

TEST(side_channel, test_connector_alloc_discard)
{
    SideChannel* sc = SideChannelManager::get_side_channel(1);
    CHECK(sc != nullptr);
    CHECK(sc->get_direction() == Connector::CONN_DUPLEX);

    sc->set_default_port(1);

    SCMessage* msg = sc->alloc_transmit_message(30);
    CHECK(msg != nullptr);

    bool success = sc->discard_message(msg);
    CHECK(success == true);
}

TEST(side_channel, test_connector_alloc_transmit)
{
    SideChannel* sc = SideChannelManager::get_side_channel(1);
    CHECK(sc != nullptr);
    CHECK(sc->get_direction() == Connector::CONN_DUPLEX);

    sc->set_default_port(2);
    SCMessage* msg = sc->alloc_transmit_message(30);
    CHECK(msg != nullptr);
    CHECK(msg->content_length == 30);
    CHECK(msg->content != nullptr);
    CHECK(msg->hdr->port == 2);

    sc->set_message_port(msg,1);
    CHECK(msg->hdr->port == 1);

    bool success = sc->transmit_message(msg);
    CHECK(success == true);
}

static void receive_handler(SCMessage* sc_msg)
{
    CHECK(sc_msg != nullptr);
    CHECK(sc_msg->sc != nullptr);
    sc_msg->sc->discard_message(sc_msg);
}

TEST(side_channel, test_connector_receive_process_dispatch_discard)
{
    SideChannel* sc = SideChannelManager::get_side_channel(1);
    CHECK(sc != nullptr);

    sc->register_receive_handler(receive_handler);

    bool success = sc->process(1);
    CHECK(success == true);

    sc->unregister_receive_handler();
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

