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

// file_connector_test.cc author Ed Borgoyn <eborgoyn@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "connectors/file_connector/file_connector.h"
#include "connectors/file_connector/file_connector_module.h"

#include "main/snort_debug.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

extern const BaseApi* file_connector;
ConnectorApi* fc_api = nullptr;

FileConnectorConfig connector_tx_text_config;
FileConnectorConfig connector_rx_text_config;
FileConnectorConfig connector_tx_binary_config;
FileConnectorConfig connector_rx_binary_config;

Module* mod;

ConnectorCommon* connector_common;

Connector* connector_tt;
Connector* connector_rt;
Connector* connector_tb;
Connector* connector_rb;

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*) { }

namespace snort
{
const char* get_instance_file(std::string& file, const char* name)
{ file += name; return nullptr; }
}

FileConnectorModule::FileConnectorModule() :
    Module("FC", "FC Help", nullptr)
{ }

FileConnectorConfig::FileConnectorConfigSet* FileConnectorModule::get_and_clear_config()
{
    FileConnectorConfig::FileConnectorConfigSet* config_set =
        new FileConnectorConfig::FileConnectorConfigSet;

    return config_set;
}

FileConnectorModule::~FileConnectorModule() = default;

ProfileStats* FileConnectorModule::get_profile() const { return nullptr; }

bool FileConnectorModule::set(const char*, Value&, SnortConfig*) { return true; }
bool FileConnectorModule::begin(const char*, int, SnortConfig*) { return true; }
bool FileConnectorModule::end(const char*, int, SnortConfig*) { return true; }

const PegInfo* FileConnectorModule::get_pegs() const { return nullptr; }
PegCount* FileConnectorModule::get_counts() const { return nullptr; }

TEST_GROUP(file_connector)
{
    void setup() override
    {
        // FIXIT-L workaround for CppUTest mem leak detector issue
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        fc_api = (ConnectorApi*)file_connector;
        connector_tx_text_config.direction = Connector::CONN_TRANSMIT;
        connector_tx_text_config.connector_name = "tx_t";
        connector_tx_text_config.name = "tx_t";
        connector_tx_text_config.text_format = true;
        connector_rx_text_config.direction = Connector::CONN_RECEIVE;
        connector_rx_text_config.connector_name = "rx_t";
        connector_rx_text_config.name = "rx_t";
        connector_rx_text_config.text_format = true;
        connector_tx_binary_config.direction = Connector::CONN_TRANSMIT;
        connector_tx_binary_config.connector_name = "tx_t";
        connector_tx_binary_config.name = "tx_t";
        connector_tx_binary_config.text_format = false;
        connector_rx_binary_config.direction = Connector::CONN_RECEIVE;
        connector_rx_binary_config.connector_name = "rx_t";
        connector_rx_binary_config.name = "rx_t";
        connector_rx_binary_config.text_format = false;
    }

    void teardown() override
    {
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(file_connector, mod_ctor_dtor)
{
    CHECK(file_connector != nullptr);
    mod = file_connector->mod_ctor();
    CHECK(mod != nullptr);
    file_connector->mod_dtor(mod);
}

TEST(file_connector, mod_instance_ctor_dtor)
{
    CHECK(file_connector != nullptr);
    mod = file_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = fc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    fc_api->dtor(connector_common);
    file_connector->mod_dtor(mod);
}

TEST_GROUP(file_connector_tinit_tterm)
{
    void setup() override
    {
        // FIXIT-L workaround for CppUTest mem leak detector issue
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        fc_api = (ConnectorApi*)file_connector;
        connector_tx_text_config.direction = Connector::CONN_TRANSMIT;
        connector_tx_text_config.connector_name = "tx_t";
        connector_tx_text_config.name = "tx_t";
        connector_tx_text_config.text_format = true;
        connector_rx_text_config.direction = Connector::CONN_RECEIVE;
        connector_rx_text_config.connector_name = "rx_t";
        connector_rx_text_config.name = "rx_t";
        connector_rx_text_config.text_format = true;
        connector_tx_binary_config.direction = Connector::CONN_TRANSMIT;
        connector_tx_binary_config.connector_name = "tx_b";
        connector_tx_binary_config.name = "tx_b";
        connector_tx_binary_config.text_format = false;
        connector_rx_binary_config.direction = Connector::CONN_RECEIVE;
        connector_rx_binary_config.connector_name = "rx_b";
        connector_rx_binary_config.name = "rx_b";
        connector_rx_binary_config.text_format = false;
        CHECK(file_connector != nullptr);
        mod = file_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = fc_api->ctor(mod);
        CHECK(connector_common != nullptr);
        connector_tt = fc_api->tinit(&connector_tx_text_config);
        connector_rt = fc_api->tinit(&connector_rx_text_config);
        connector_tb = fc_api->tinit(&connector_tx_binary_config);
        connector_rb = fc_api->tinit(&connector_rx_binary_config);
        CHECK(connector_tt != nullptr);
        CHECK(connector_rt != nullptr);
        CHECK(connector_tb != nullptr);
        CHECK(connector_rb != nullptr);
    }

    void teardown() override
    {
        fc_api->tterm(connector_tt);
        fc_api->tterm(connector_rt);
        fc_api->tterm(connector_tb);
        fc_api->tterm(connector_rb);
        fc_api->dtor(connector_common);
        file_connector->mod_dtor(mod);
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(file_connector_tinit_tterm, alloc_discard)
{
    const uint8_t* data = nullptr;
    FileConnector* fc_rt = (FileConnector*)connector_rt;

    FileConnectorMsgHandle* handle = (FileConnectorMsgHandle*)(fc_rt->alloc_message(40,&data));
    CHECK(data != nullptr);
    CHECK(handle->connector_msg.length == 40);
    CHECK(handle->connector_msg.data == data);
    fc_rt->discard_message(handle);
}

TEST_GROUP(file_connector_text)
{
    void setup() override
    {
        // FIXIT-L workaround for CppUTest mem leak detector issue
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        fc_api = (ConnectorApi*)file_connector;
        connector_tx_text_config.direction = Connector::CONN_TRANSMIT;
        connector_tx_text_config.connector_name = "tx_t";
        connector_tx_text_config.name = "tx_t";
        connector_tx_text_config.text_format = true;
        connector_rx_text_config.direction = Connector::CONN_RECEIVE;
        connector_rx_text_config.connector_name = "rx_t";
        connector_rx_text_config.name = "rx_t";
        connector_rx_text_config.text_format = true;
        CHECK(file_connector != nullptr);
    }

    void teardown() override
    {
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(file_connector_text, alloc_transmit_rename_receive_discard)
{
    mod = file_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = fc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    connector_tt = fc_api->tinit(&connector_tx_text_config);
    CHECK(connector_tt != nullptr);
    FileConnector* fc_tt = (FileConnector*)connector_tt;

    const uint8_t* data = nullptr;
    FileConnectorMsgHandle* t_handle = (FileConnectorMsgHandle*)(fc_tt->alloc_message(40,&data));
    CHECK(data != nullptr);
    CHECK(t_handle->connector_msg.length == 40);
    CHECK(t_handle->connector_msg.data == data);
    CHECK(fc_tt->transmit_message(t_handle) == true);

    fc_api->tterm(connector_tt);
    fc_api->dtor(connector_common);
    file_connector->mod_dtor(mod);

    std::rename("file_connector_tx_t_transmit", "file_connector_rx_t_receive");

    mod = file_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = fc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    connector_rt = fc_api->tinit(&connector_rx_text_config);
    CHECK(connector_rt != nullptr);
    FileConnector* fc_rt = (FileConnector*)connector_rt;

    FileConnectorMsgHandle* r_handle = (FileConnectorMsgHandle*)(fc_rt->receive_message(true));
    CHECK(r_handle != nullptr);
    CHECK(r_handle->connector_msg.length == 40);

    fc_rt->discard_message(r_handle);

    fc_api->tterm(connector_rt);
    fc_api->dtor(connector_common);
    file_connector->mod_dtor(mod);
}

TEST_GROUP(file_connector_binary)
{
    void setup() override
    {
        // FIXIT-L workaround for CppUTest mem leak detector issue
        MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        fc_api = (ConnectorApi*)file_connector;
        connector_tx_binary_config.direction = Connector::CONN_TRANSMIT;
        connector_tx_binary_config.connector_name = "tx_b";
        connector_tx_binary_config.name = "tx_b";
        connector_tx_binary_config.text_format = false;
        connector_rx_binary_config.direction = Connector::CONN_RECEIVE;
        connector_rx_binary_config.connector_name = "rx_b";
        connector_rx_binary_config.name = "rx_b";
        connector_rx_binary_config.text_format = false;
        CHECK(file_connector != nullptr);
    }

    void teardown() override
    {
        MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(file_connector_binary, alloc_transmit_rename_receive_discard)
{
    mod = file_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = fc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    connector_tb = fc_api->tinit(&connector_tx_binary_config);
    CHECK(connector_tb != nullptr);
    FileConnector* fc_tb = (FileConnector*)connector_tb;

    const uint8_t* data = nullptr;
    FileConnectorMsgHandle* t_handle = (FileConnectorMsgHandle*)(fc_tb->alloc_message(40,&data));
    CHECK(data != nullptr);
    CHECK(t_handle->connector_msg.length == 40);
    CHECK(t_handle->connector_msg.data == data);
    CHECK(fc_tb->transmit_message(t_handle) == true);

    fc_api->tterm(connector_tb);
    fc_api->dtor(connector_common);
    file_connector->mod_dtor(mod);

    std::rename("file_connector_tx_b_transmit", "file_connector_rx_b_receive");

    mod = file_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = fc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    connector_rb = fc_api->tinit(&connector_rx_binary_config);
    CHECK(connector_rb != nullptr);
    FileConnector* fc_rb = (FileConnector*)connector_rb;

    FileConnectorMsgHandle* r_handle = (FileConnectorMsgHandle*)(fc_rb->receive_message(true));
    CHECK(r_handle != nullptr);
    CHECK(r_handle->connector_msg.length == 40);

    fc_rb->discard_message(r_handle);

    fc_api->tterm(connector_rb);
    fc_api->dtor(connector_common);
    file_connector->mod_dtor(mod);
}

TEST_GROUP(file_connector_msg_handle)
{
    void setup() override
    {
    }

    void teardown() override
    {
    }
};

TEST(file_connector_msg_handle, test)
{
    FileConnectorMsgHandle handle(12);
    CHECK(handle.connector_msg.length == 12);
    CHECK(handle.connector_msg.data != nullptr);
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    std::remove("file_connector_rx_b_receive");
    std::remove("file_connector_tx_b_transmit");
    std::remove("file_connector_rx_t_receive");
    std::remove("file_connector_tx_t_transmit");
    return return_value;
}

