//--------------------------------------------------------------------------
// Copyright (C) 2015-2025 Cisco and/or its affiliates. All rights reserved.
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
#include "side_channel/side_channel_format.h"

#include "log/messages.h"
#include "managers/connector_manager.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

ConnectorConfig duplex_conf;

class DuplexConnector : public Connector
{
public:
    DuplexConnector() : Connector(duplex_conf) { }

    bool transmit_message(const ConnectorMsg&, const Connector::ID&) override
    { return true; }
    bool transmit_message(const ConnectorMsg&&, const Connector::ID&) override
    { return true; }
    ConnectorMsg receive_message(bool) override
    {
        const uint32_t length = 30;
        uint8_t* data = new uint8_t[sizeof(SCMsgHdr) + length];

        return ConnectorMsg(data, length, true);
    }
};

ConnectorConfig receive_conf;

class ReceiveConnector : public Connector
{
public:
    ReceiveConnector() : Connector(receive_conf) { }

    bool transmit_message(const ConnectorMsg&, const Connector::ID&) override
    { return false; }
    bool transmit_message(const ConnectorMsg&&, const Connector::ID&) override
    { return false; }
    ConnectorMsg receive_message(bool) override
    {
        const uint32_t length = 30;
        uint8_t* data = new uint8_t[sizeof(SCMsgHdr) + length];

        return ConnectorMsg(data, length, true);
    }
};

ConnectorConfig transmit_conf;

class TransmitConnector : public Connector
{
public:
    TransmitConnector() : Connector(transmit_conf) { }

    bool transmit_message(const ConnectorMsg&, const Connector::ID&) override
    { return true; }
    bool transmit_message(const ConnectorMsg&&, const Connector::ID&) override
    { return true; }
    ConnectorMsg receive_message(bool) override
    { return ConnectorMsg(); }
};

Connector* receive_connector = nullptr;
Connector* transmit_connector = nullptr;
Connector* duplex_connector = nullptr;

void ConnectorManager::thread_init()
{
    receive_conf.direction = Connector::Direction::CONN_RECEIVE;
    receive_connector = new ReceiveConnector;
    transmit_conf.direction = Connector::Direction::CONN_TRANSMIT;
    transmit_connector = new TransmitConnector;
    duplex_conf.direction = Connector::Direction::CONN_DUPLEX;
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

std::string text_test_hdr;
std::string sc_msg_hdr_to_text(const SCMsgHdr*)
{ return text_test_hdr; }

std::string text_test_data;
std::string sc_msg_data_to_text(const uint8_t*, uint32_t)
{ return text_test_data; }

ConnectorMsg converted_test_msg;
ConnectorMsg from_text(const char*, uint32_t)
{ return std::move(converted_test_msg); }


TEST_GROUP(side_channel)
{
    void setup() override
    {
        SideChannelManager::pre_config_init();
        SCConnectors test_connectors;
        PortBitSet test_ports;

        test_connectors.emplace_back("R");
        test_connectors.emplace_back("T");
        test_ports.set(1);

        SideChannelManager::instantiate(&test_connectors, &test_ports, ScMsgFormat::BINARY);

        test_connectors.clear();
        test_ports.reset(1);

        test_connectors.emplace_back("R");
        test_ports.set(2);

        SideChannelManager::instantiate(&test_connectors, &test_ports, ScMsgFormat::BINARY);

        test_connectors.clear();
        test_ports.reset(2);

        test_connectors.emplace_back("T");
        test_ports.set(3);

        SideChannelManager::instantiate(&test_connectors, &test_ports, ScMsgFormat::BINARY);

        test_connectors.clear();
        test_ports.reset(3);

        test_ports.set(4);

        SideChannelManager::instantiate(&test_connectors, &test_ports, ScMsgFormat::BINARY);

        test_connectors.clear();
        test_ports.reset(4);

        test_connectors.emplace_back("D");
        test_ports.set(5);

        SideChannelManager::instantiate(&test_connectors, &test_ports, ScMsgFormat::BINARY);

        test_connectors.clear();
        test_ports.reset(5);

        test_connectors.emplace_back("R");
        test_ports.set(6);

        SideChannelManager::instantiate(&test_connectors, &test_ports, ScMsgFormat::TEXT);

        test_connectors.clear();
        test_ports.reset(6);

        test_connectors.emplace_back("T");
        test_ports.set(7);

        SideChannelManager::instantiate(&test_connectors, &test_ports, ScMsgFormat::TEXT);

        test_connectors.clear();
        test_ports.reset(7);

        ConnectorManager::thread_init();
        SideChannelManager::thread_init();
    }

    void teardown() override
    {
        ConnectorManager::thread_term();
        SideChannelManager::thread_term();
        SideChannelManager::term();

        text_test_hdr.clear();
        text_test_data.clear();
    }
};

TEST(side_channel, test_connector_get_none)
{
    const SideChannel* sc = SideChannelManager::get_side_channel(8);
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

TEST(side_channel, test_connector_alloc_discard_binary)
{
    SideChannel* sc = SideChannelManager::get_side_channel(1);
    CHECK(sc != nullptr);
    CHECK(sc->get_direction() == Connector::CONN_DUPLEX);

    sc->set_default_port(1);

    SCMessage* msg = sc->alloc_transmit_message(30);
    CHECK(msg != nullptr);

    CHECK(sc->discard_message(msg) == true);
}

TEST(side_channel, test_connector_alloc_discard_text)
{
    SideChannel* sc = SideChannelManager::get_side_channel(7);
    CHECK(sc != nullptr);

    sc->set_default_port(1);
    text_test_hdr = "1:2.3";

    SCMessage* msg = sc->alloc_transmit_message(30);
    CHECK(msg != nullptr);

    bool success = sc->discard_message(msg);
    CHECK(success == true);
}

TEST(side_channel, test_connector_alloc_text_invalid_hdr)
{
    SideChannel* sc = SideChannelManager::get_side_channel(7);
    CHECK(sc != nullptr);

    sc->set_default_port(1);
    text_test_hdr = "";

    const SCMessage* msg = sc->alloc_transmit_message(30);
    CHECK(msg == nullptr);
}

TEST(side_channel, test_connector_alloc_transmit_binary)
{
    SideChannel* sc = SideChannelManager::get_side_channel(1);
    CHECK(sc != nullptr);
    CHECK(sc->get_direction() == Connector::CONN_DUPLEX);

    sc->set_default_port(2);
    SCMessage* msg = sc->alloc_transmit_message(30);
    CHECK(msg != nullptr);
    CHECK(msg->content_length == 30);
    CHECK(msg->content != nullptr);

    CHECK(msg->cmsg.get_length() == 30 + sizeof(SCMsgHdr));
    CHECK(msg->cmsg.get_data() != nullptr);

    CHECK(((SCMsgHdr*)msg->cmsg.get_data())->port == 2);
;
    CHECK(sc->transmit_message(msg) == true);
}

TEST(side_channel, test_connector_alloc_transmit_text)
{
    SideChannel* sc = SideChannelManager::get_side_channel(7);
    CHECK(sc != nullptr);

    sc->set_default_port(2);
    text_test_hdr = "1:2.3";
    text_test_data = ",01,02,03";

    SCMessage* msg = sc->alloc_transmit_message(3);
    CHECK(msg != nullptr);
    CHECK(msg->content_length == 3);
    CHECK(msg->content != nullptr);

    CHECK(msg->cmsg.get_length() == 3 * TXT_UNIT_LEN + sc_msg_hdr_to_text(nullptr).length());
    CHECK(msg->cmsg.get_data() != nullptr);

    CHECK(sc->transmit_message(msg) == true);
}

TEST(side_channel, test_connector_alloc_transmit_text_invalid_data)
{
    SideChannel* sc = SideChannelManager::get_side_channel(7);
    CHECK(sc != nullptr);

    sc->set_default_port(2);
    text_test_hdr = "1:2.3";
    text_test_data = "";

    SCMessage* msg = sc->alloc_transmit_message(3);
    CHECK(msg != nullptr);

    CHECK(sc->transmit_message(msg) == false);
}

static void receive_handler(SCMessage* sc_msg)
{
    CHECK(sc_msg != nullptr);
    CHECK(sc_msg->cmsg.get_data() != nullptr);
    CHECK(sc_msg->cmsg.get_length() != 0);
    CHECK(sc_msg->sc != nullptr);
    CHECK(sc_msg->connector != nullptr);
    sc_msg->sc->discard_message(sc_msg);
}

TEST(side_channel, test_connector_receive_process_dispatch_discard_binary)
{
    SideChannel* sc = SideChannelManager::get_side_channel(1);
    CHECK(sc != nullptr);
    sc->register_receive_handler(receive_handler);

    CHECK(sc->process(1) == true);

    sc->unregister_receive_handler();
}

TEST(side_channel, test_connector_receive_process_dispatch_discard_text)
{
    SideChannel* sc = SideChannelManager::get_side_channel(6);
    CHECK(sc != nullptr);
    sc->register_receive_handler(receive_handler);

    converted_test_msg = ConnectorMsg((uint8_t*)"test", sizeof("test"), false);
    CHECK(sc->process(1) == true);

    sc->unregister_receive_handler();
}

TEST(side_channel, test_connector_receive_process_dispatch_discard_text_invalid)
{
    SideChannel* sc = SideChannelManager::get_side_channel(6);
    CHECK(sc != nullptr);
    sc->register_receive_handler(receive_handler);

    converted_test_msg = ConnectorMsg();

    CHECK(sc->process(1) == false);

    sc->unregister_receive_handler();
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

