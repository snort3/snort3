//--------------------------------------------------------------------------
// Copyright (C) 2015-2016 Cisco and/or its affiliates. All rights reserved.
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

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

#include "side_channel/side_channel.h"
#include "side_channel/side_channel_module.h"

#include "log/messages.h"
#include "main/snort_debug.h"
#include "managers/connector_manager.h"

class TestConnector : public Connector
{
    ConnectorMsgHandle* alloc_message(const uint32_t, const uint8_t**) { return nullptr; }
    void discard_message(ConnectorMsgHandle*) { }
    bool transmit_message(ConnectorMsgHandle*) { return true; }
    ConnectorMsgHandle* receive_message(bool) { return nullptr; }
    ConnectorMsg* get_connector_msg(ConnectorMsgHandle*) { return nullptr; }
    Direction get_connector_direction() { return CONN_UNDEFINED; }
};

class ReceiveConnector : public Connector
{
    ConnectorMsgHandle* alloc_message(const uint32_t, const uint8_t**) { return nullptr; }
    void discard_message(ConnectorMsgHandle*) { }
    bool transmit_message(ConnectorMsgHandle*) { return true; }
    ConnectorMsgHandle* receive_message(bool) { return nullptr; }
    ConnectorMsg* get_connector_msg(ConnectorMsgHandle*) { return nullptr; }
    Direction get_connector_direction() { return CONN_RECEIVE; }
};

class TransmitConnector : public Connector
{
    ConnectorMsgHandle* alloc_message(const uint32_t, const uint8_t**) { return nullptr; }
    void discard_message(ConnectorMsgHandle*) { }
    bool transmit_message(ConnectorMsgHandle*) { return true; }
    ConnectorMsgHandle* receive_message(bool) { return nullptr; }
    ConnectorMsg* get_connector_msg(ConnectorMsgHandle*) { return nullptr; }
    Direction get_connector_direction() { return CONN_TRANSMIT; }
};

void ConnectorManager::thread_init() { }

void ConnectorManager::thread_term() { }

Connector* ConnectorManager::get_connector(const std::string connector_name)
{
    if ( connector_name == "U" )
        return new TestConnector();
    else if ( connector_name == "R" )
        return new ReceiveConnector();
    else if ( connector_name == "T" )
        return new TransmitConnector();
    else
        return nullptr;
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }

void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*) { }

void ParseWarning(WarningGroup, const char*, ...) { }

void Debug::print(const char*, int, uint64_t, const char*, ...) { }

TEST_GROUP(side_channel)
{
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(side_channel, test)
{
    CHECK(1==1);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}

