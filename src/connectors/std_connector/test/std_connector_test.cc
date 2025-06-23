//--------------------------------------------------------------------------
// Copyright (C) 2024-2025 Cisco and/or its affiliates. All rights reserved.
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

// std_connector_test.cc author Vitalii Horbatov <vhorbato@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <sstream>

#include "connectors/std_connector/std_connector.h"
#include "main/thread_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

StdConnectorBuffer::StdConnectorBuffer(const char*) {}
StdConnectorBuffer::~StdConnectorBuffer() {}
void StdConnectorBuffer::start() {}
Ring2::Writer StdConnectorBuffer::acquire(unsigned long) { return Ring2(0).writer(); }
bool StdConnectorBuffer::release(Ring2::Writer const&) { return false; }

using namespace snort;

extern const BaseApi* std_connector;
const ConnectorApi* stdc_api = nullptr;

StdConnectorConfig connector_transmit_config;
StdConnectorConfig connector_receive_config;

Module* mod;

ConnectorCommon* connector_common;

Connector* connector_transmit;
Connector* connector_receive;

struct MockLog
{
    std::string accumulated_buffer;
    std::string flushed_buffer;
};

MockLog output_buffer;

namespace snort
{
TextLog* TextLog_Init(const char*, unsigned int = 0, size_t = 0, bool = true)
{
    output_buffer.accumulated_buffer.clear();
    output_buffer.flushed_buffer.clear();
    return (TextLog*)&output_buffer;
}

bool TextLog_Print(TextLog* const txt, const char* fmt, ...)
{
    MockLog* txt_mock = (MockLog*)txt;
    va_list ap;
    va_start(ap, fmt);
    char data[100];
    vsnprintf(data, 100, fmt, ap);
    txt_mock->accumulated_buffer.append(data);
    va_end(ap);
    return true;
}

bool TextLog_Flush(TextLog* const txt)
{
    MockLog* txt_mock = (MockLog*)txt;
    txt_mock->flushed_buffer.append(txt_mock->accumulated_buffer);
    txt_mock->accumulated_buffer.clear();
    return true;
}

void TextLog_Term(TextLog* txt)
{
    MockLog* txt_mock = (MockLog*)txt;
    txt_mock->accumulated_buffer.clear();
    txt_mock->flushed_buffer.clear();
}

const char* get_instance_file(std::string& file, const char* name) { file += name; return nullptr; }
unsigned get_instance_id() { return 0; }
unsigned ThreadConfig::get_instance_max() { return 1; }
}

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }

//-------------------------------------------------------------------------
// connector test
//-------------------------------------------------------------------------

TEST_GROUP(std_connector_construction)
{
    void setup() override
    {
        stdc_api = (const ConnectorApi*) std_connector;
        connector_transmit_config.direction = Connector::CONN_TRANSMIT;
        connector_transmit_config.connector_name = "std_tx";

        connector_receive_config.direction = Connector::CONN_RECEIVE;
        connector_receive_config.connector_name = "std_rx";
    }
};

TEST(std_connector_construction, mod_ctor_dtor)
{
    CHECK(std_connector != nullptr);
    mod = std_connector->mod_ctor();
    CHECK(mod != nullptr);
    std_connector->mod_dtor(mod);
}

TEST(std_connector_construction, mod_instance_ctor_dtor)
{
    CHECK(std_connector != nullptr);
    mod = std_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = stdc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    stdc_api->dtor(connector_common);
    std_connector->mod_dtor(mod);
}

TEST_GROUP(std_connector_tinit_tterm)
{
    void setup() override
    {
        stdc_api = (const ConnectorApi*)std_connector;
        connector_transmit_config.direction = Connector::CONN_TRANSMIT;
        connector_transmit_config.connector_name = "std_tx";

        connector_receive_config.direction = Connector::CONN_RECEIVE;
        connector_receive_config.connector_name = "std_rx";

        CHECK(std_connector != nullptr);
        mod = std_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = stdc_api->ctor(mod);
        CHECK(connector_common != nullptr);

        connector_transmit = stdc_api->tinit(connector_transmit_config);
        connector_receive = stdc_api->tinit(connector_receive_config);

        CHECK(connector_transmit != nullptr);
        CHECK(connector_receive != nullptr);
    }

    void teardown() override
    {
        stdc_api->tterm(connector_transmit);
        stdc_api->tterm(connector_receive);
        stdc_api->dtor(connector_common);
        std_connector->mod_dtor(mod);
    }
};

TEST_GROUP(std_connector)
{
    void setup() override
    {
        stdc_api = (const ConnectorApi*)std_connector;
        connector_transmit_config.direction = Connector::CONN_TRANSMIT;
        connector_transmit_config.connector_name = "std_tx";
        connector_receive_config.direction = Connector::CONN_RECEIVE;
        connector_receive_config.connector_name = "std_rx";
    }
};

TEST(std_connector, transmit_flush_empty)
{
    mod = std_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = stdc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    connector_transmit = stdc_api->tinit(connector_transmit_config);
    CHECK(connector_transmit != nullptr);
    StdConnector* stdc_tt = (StdConnector*)connector_transmit;

    ConnectorMsg null_msg(nullptr, 1, false);
    CHECK(stdc_tt->transmit_message(null_msg) == false);
    CHECK(output_buffer.accumulated_buffer.empty());

    uint8_t data[] = "";
    ConnectorMsg empty_msg(data, 0, false);
    CHECK(stdc_tt->transmit_message(empty_msg) == false);
    CHECK(output_buffer.accumulated_buffer.empty());

    CHECK(stdc_tt->flush());
    CHECK(output_buffer.accumulated_buffer.empty());
    CHECK(output_buffer.flushed_buffer.empty());

    stdc_api->tterm(connector_transmit);
    stdc_api->dtor(connector_common);
    std_connector->mod_dtor(mod);
}

TEST(std_connector, transmit_flush)
{
    uint32_t len = sizeof("foobar") - 1;

    mod = std_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = stdc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    connector_transmit = stdc_api->tinit(connector_transmit_config);
    CHECK(connector_transmit != nullptr);
    StdConnector* stdc_tt = (StdConnector*)connector_transmit;

    uint8_t* data = new uint8_t[len];
    memcpy(data, "foobar", len);
    ConnectorMsg t_msg(data, len, true);

    CHECK(stdc_tt->transmit_message(t_msg));
    CHECK(output_buffer.accumulated_buffer == "foobar\n");

    CHECK(stdc_tt->flush());
    CHECK(output_buffer.accumulated_buffer.empty());
    CHECK(output_buffer.flushed_buffer == "foobar\n");

    stdc_api->tterm(connector_transmit);
    stdc_api->dtor(connector_common);
    std_connector->mod_dtor(mod);
}


TEST(std_connector, move_transmit_flush)
{
    uint32_t len = sizeof("foobar") - 1;

    mod = std_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = stdc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    connector_transmit = stdc_api->tinit(connector_transmit_config);
    CHECK(connector_transmit != nullptr);
    StdConnector* stdc_tt = (StdConnector*)connector_transmit;

    uint8_t* data = new uint8_t[len];
    memcpy(data, "foobar", len);
    ConnectorMsg t_msg(data, len, true);

    CHECK(stdc_tt->transmit_message(std::move(t_msg)));
    CHECK(output_buffer.accumulated_buffer == "foobar\n");

    CHECK(stdc_tt->flush());
    CHECK(output_buffer.accumulated_buffer.empty());
    CHECK(output_buffer.flushed_buffer == "foobar\n");

    stdc_api->tterm(connector_transmit);
    stdc_api->dtor(connector_common);
    std_connector->mod_dtor(mod);
}

TEST(std_connector, receive)
{
    mod = std_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = stdc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    connector_receive = stdc_api->tinit(connector_receive_config);
    CHECK(connector_receive != nullptr);
    StdConnector* stdc_rt = (StdConnector*)connector_receive;

    std::istringstream ss("foo\nbar\n");
    std::cin.rdbuf(ss.rdbuf());

    ConnectorMsg msg = stdc_rt->receive_message(false);
    CHECK(std::string((char*)msg.get_data(), msg.get_length()) == "foo");

    msg = stdc_rt->receive_message(false);
    CHECK(std::string((char*)msg.get_data(), msg.get_length()) == "bar");

    stdc_api->tterm(connector_receive);
    stdc_api->dtor(connector_common);
    std_connector->mod_dtor(mod);
}

//-------------------------------------------------------------------------
// module test
//-------------------------------------------------------------------------

TEST_GROUP(std_connector_module)
{
};

TEST(std_connector_module, test)
{
    Value r_connector_val("rx");
    Value r_direction_val((uint64_t)0);

    Value t_connector_val("tx");
    Value t_direction_val((uint64_t)1);

    Value d_connector_val("duplex");
    Value d_direction_val((uint64_t)2);

    Parameter direction_param =
        {"direction", Parameter::PT_ENUM, "receive | transmit | duplex", nullptr, "direction"};
    Parameter connector_param =
        {"connector", Parameter::PT_STRING, nullptr, nullptr, "connector"};

    StdConnectorModule module;

    r_direction_val.set(&direction_param);
    r_connector_val.set(&connector_param);

    t_direction_val.set(&direction_param);
    t_connector_val.set(&connector_param);

    d_direction_val.set(&direction_param);
    d_connector_val.set(&connector_param);

    module.begin("std_connector", 0, nullptr);
    module.begin("std_connector", 1, nullptr);
    module.set("std_connector.direction", r_direction_val, nullptr);
    module.set("std_connector.connector", r_connector_val, nullptr);
    module.end("std_connector", 1, nullptr);
    module.begin("std_connector", 1, nullptr);
    module.set("std_connector.direction", t_direction_val, nullptr);
    module.set("std_connector.connector", t_connector_val, nullptr);
    module.end("std_connector", 1, nullptr);
    module.begin("std_connector", 1, nullptr);
    module.set("std_connector.direction", d_direction_val, nullptr);
    module.set("std_connector.connector", d_connector_val, nullptr);
    module.end("std_connector", 1, nullptr);
    module.end("std_connector", 0, nullptr);

    ConnectorConfig::ConfigSet config_set = module.get_and_clear_config();

    CHECK(6 == config_set.size());

    ConnectorConfig config = *(config_set[0]);
    CHECK("stdout" == config.connector_name);
    CHECK(Connector::CONN_TRANSMIT == config.direction);

    config = *(config_set[1]);
    CHECK("stdin" == config.connector_name);
    CHECK(Connector::CONN_RECEIVE == config.direction);

    config = *(config_set[2]);
    CHECK("stdio" == config.connector_name);
    CHECK(Connector::CONN_DUPLEX == config.direction);

    config = *(config_set[3]);
    CHECK("rx" == config.connector_name);
    CHECK(Connector::CONN_RECEIVE == config.direction);

    config = *(config_set[4]);
    CHECK("tx" == config.connector_name);
    CHECK(Connector::CONN_TRANSMIT == config.direction);

    config = *(config_set[5]);
    CHECK("duplex" == config.connector_name);
    CHECK(Connector::CONN_DUPLEX == config.direction);
}

int main(int argc, char** argv)
{
    return CommandLineTestRunner::RunAllTests(argc, argv);
}
