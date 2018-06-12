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

// tcp_connector_test.cc author Ed Borgoyn <eborgoyn@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "connectors/tcp_connector/tcp_connector.h"
#include "connectors/tcp_connector/tcp_connector_module.h"

#include <netdb.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "main/snort_debug.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

extern const BaseApi* tcp_connector;
ConnectorApi* tcpc_api = nullptr;

static unsigned s_instance = 0;
static unsigned char* s_rec_message = nullptr;
static size_t s_rec_message_size = 0;
static int s_socket_return = 1;
static int s_bind_return = 0;
static int s_listen_return = 0;
static int s_accept_return = 2;
static int s_connect_return = 1;
static bool s_poll_error = false;
static bool s_poll_undesirable = false;
static bool s_poll_data_available = false;
static int s_rec_error = 0;
static int s_rec_error_size = -1;
static bool s_rec_return_zero = false;

static int s_send_ret_header = sizeof(TcpConnectorMsgHdr);
static int s_send_ret_other = 0;

TcpConnectorConfig connector_config;

Module* mod;

ConnectorCommon* connector_common;

Connector* connector;

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*) { }
void show_stats(PegCount*, const PegInfo*, IndexVec&, const char*, FILE*) { }

namespace snort
{
unsigned get_instance_id()
{ return s_instance; }

void ErrorMessage(const char*, ...) { }
void LogMessage(const char*, ...) { }
}

int connect (int, const struct sockaddr*, socklen_t) { return s_connect_return; } 
ssize_t send (int, const void*, size_t n, int)
{
    if ( n == sizeof(TcpConnectorMsgHdr) )
        return s_send_ret_header;
    else
        return s_send_ret_other;
}

int poll (struct pollfd* fds, nfds_t nfds, int)
{
    if ( s_poll_error )
        return -1;

    if ( s_poll_undesirable )
    {
        fds[0].revents |= POLLHUP;
        return 1;
    }

    if ( (nfds > 0) && s_poll_data_available )
    {
        fds[0].revents |= POLLIN;
        return 1;
    }
    else
        return 0;
}

ssize_t recv (int, void *buf, size_t n, int)
{
    if ( (s_rec_error_size == -1) ||
         (s_rec_error_size == (int)n) )
    {
        if ( s_rec_return_zero )
            return 0;

        if ( (errno = s_rec_error) != 0 )
        {
            s_rec_error = 0;
            return -1;
        }
    }

    if ( (s_rec_message != nullptr)  && (s_rec_message_size >= n) )
    {
        memcpy( buf, s_rec_message, n);
        s_rec_message_size -= n;
        s_rec_message += n;
        return (ssize_t)n;
    }
    else
        return 0;
}

#ifdef __FreeBSD__
int socket (int, int, int) { return s_socket_return; }
int bind (int, const struct sockaddr*, socklen_t) { return s_bind_return; }
int listen (int, int) { return s_listen_return; }
#else
int socket (int, int, int) __THROW { return s_socket_return; }
int bind (int, const struct sockaddr*, socklen_t) __THROW { return s_bind_return; }
int listen (int, int) __THROW { return s_listen_return; }
#endif

int accept (int, struct sockaddr*, socklen_t*) { return s_accept_return; }
int close (int) { return 0; }

static void set_normal_status()
{
    s_instance = 0;
    s_rec_message = nullptr;
    s_rec_message_size = 0;
    s_socket_return = 1;
    s_bind_return = 0;
    s_listen_return = 0;
    s_accept_return = 2;
    s_send_ret_header = sizeof(TcpConnectorMsgHdr);
    s_send_ret_other = 0;
    s_connect_return = 1;
    s_send_ret_header = sizeof(TcpConnectorMsgHdr);
    s_send_ret_other = 0;
    s_poll_error = false;
    s_poll_undesirable = false;
    s_poll_data_available = false;
    s_rec_error = 0;
    s_rec_error_size = -1;
    s_rec_return_zero = false;
}

TcpConnectorModule::TcpConnectorModule() :
    Module("TCPC", "TCPC Help", nullptr)
{ }

TcpConnectorConfig::TcpConnectorConfigSet* TcpConnectorModule::get_and_clear_config()
{
    TcpConnectorConfig::TcpConnectorConfigSet* config_set = new TcpConnectorConfig::TcpConnectorConfigSet;

    return config_set;
}

TcpConnectorModule::~TcpConnectorModule() = default;

ProfileStats* TcpConnectorModule::get_profile() const { return nullptr; }

bool TcpConnectorModule::set(const char*, Value&, SnortConfig*) { return true; }
bool TcpConnectorModule::begin(const char*, int, SnortConfig*) { return true; }
bool TcpConnectorModule::end(const char*, int, SnortConfig*) { return true; }

const PegInfo* TcpConnectorModule::get_pegs() const { return nullptr; }
PegCount* TcpConnectorModule::get_counts() const { return nullptr; }

TEST_GROUP(tcp_connector)
{
    void setup() override
    {
        // FIXIT-L workaround for CppUTest mem leak detector issue
        //MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        tcpc_api = (ConnectorApi*)tcp_connector;
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp";
        connector_config.address = "127.0.0.1";
        connector_config.base_port = 10000;
        connector_config.setup = TcpConnectorConfig::Setup::CALL;
        connector_config.async_receive = false;
    }

    void teardown() override
    {
        //MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(tcp_connector, mod_ctor_dtor)
{
    CHECK(tcp_connector != nullptr);
    mod = tcp_connector->mod_ctor();
    CHECK(mod != nullptr);
    tcp_connector->mod_dtor(mod);
}

TEST(tcp_connector, mod_instance_ctor_dtor)
{
    CHECK(tcp_connector != nullptr);
    mod = tcp_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = tcpc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    tcpc_api->dtor(connector_common);
    tcp_connector->mod_dtor(mod);
}

TEST_GROUP(tcp_connector_call_error)
{
    void setup() override
    {
        // FIXIT-L workaround for CppUTest mem leak detector issue
        //MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        tcpc_api = (ConnectorApi*)tcp_connector;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp";
        connector_config.address = "127.0.0.1";
        connector_config.base_port = 10000;
        connector_config.setup = TcpConnectorConfig::Setup::CALL;
        connector_config.async_receive = false;
        CHECK(tcp_connector != nullptr);
        mod = tcp_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = tcpc_api->ctor(mod);
        CHECK(connector_common != nullptr);
    }

    void teardown() override
    {
        connector = tcpc_api->tinit(&connector_config);
        CHECK(connector == nullptr);
        tcpc_api->dtor(connector_common);
        tcp_connector->mod_dtor(mod);
        //MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST_GROUP(tcp_connector_call_other)
{
    void setup() override
    {
        // FIXIT-L workaround for CppUTest mem leak detector issue
        //MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    }

    void teardown() override
    {
        //MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST_GROUP(tcp_connector_answer_error)
{
    void setup() override
    {
        // FIXIT-L workaround for CppUTest mem leak detector issue
        //MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        tcpc_api = (ConnectorApi*)tcp_connector;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp-a";
        connector_config.base_port = 20000;
        connector_config.setup = TcpConnectorConfig::Setup::ANSWER;
        connector_config.async_receive = false;
        CHECK(tcp_connector != nullptr);
        mod = tcp_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = tcpc_api->ctor(mod);
        CHECK(connector_common != nullptr);
    }

    void teardown() override
    {
        connector = tcpc_api->tinit(&connector_config);
        CHECK(connector == nullptr);
        tcpc_api->tterm(connector);
        tcpc_api->dtor(connector_common);
        tcp_connector->mod_dtor(mod);
        //MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(tcp_connector_call_error, bad_port)
{
    s_instance = 65000;
}

TEST(tcp_connector_call_error, bad_socket)
{
    s_socket_return = -1;
}

TEST(tcp_connector_call_error, bad_connect)
{
    s_connect_return = -1;
}

TEST(tcp_connector_answer_error, bad_socket)
{
    s_socket_return = -1;
}

TEST(tcp_connector_answer_error, bad_bind)
{
    s_bind_return = -1;
}

TEST(tcp_connector_answer_error, bad_listen)
{
    s_listen_return = -1;
}

TEST(tcp_connector_answer_error, bad_accept)
{
    s_accept_return = -1;
}

TEST(tcp_connector_call_other, bad_setup)
{
    tcpc_api = (ConnectorApi*)tcp_connector;
    s_instance = 0;
    set_normal_status();
    connector_config.direction = Connector::CONN_DUPLEX;
    connector_config.connector_name = "tcp";
    connector_config.address = "127.0.0.1";
    connector_config.base_port = 10000;
    connector_config.setup = (TcpConnectorConfig::Setup)(-1);
    connector_config.async_receive = false;
    CHECK(tcp_connector != nullptr);
    mod = tcp_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = tcpc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    connector = tcpc_api->tinit(&connector_config);
    CHECK(connector == nullptr);
    tcpc_api->dtor(connector_common);
    tcp_connector->mod_dtor(mod);
}

TEST_GROUP(tcp_connector_tinit_tterm_thread_call)
{
    void setup() override
    {
        // FIXIT-L workaround for CppUTest mem leak detector issue
        //MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        tcpc_api = (ConnectorApi*)tcp_connector;
        s_instance = 0;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp";
        connector_config.address = "127.0.0.1";
        connector_config.base_port = 10000;
        connector_config.setup = TcpConnectorConfig::Setup::CALL;
        connector_config.async_receive = true;
        CHECK(tcp_connector != nullptr);
        mod = tcp_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = tcpc_api->ctor(mod);
        CHECK(connector_common != nullptr);
        connector = tcpc_api->tinit(&connector_config);
        CHECK(connector != nullptr);
        CHECK(connector->get_connector_direction() == Connector::CONN_DUPLEX);
    }

    void teardown() override
    {
        tcpc_api->tterm(connector);
        tcpc_api->dtor(connector_common);
        tcp_connector->mod_dtor(mod);
        //MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST_GROUP(tcp_connector_tinit_tterm_call)
{
    void setup() override
    {
        // FIXIT-L workaround for CppUTest mem leak detector issue
        //MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        tcpc_api = (ConnectorApi*)tcp_connector;
        s_instance = 0;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp";
        connector_config.address = "127.0.0.1";
        connector_config.base_port = 10000;
        connector_config.setup = TcpConnectorConfig::Setup::CALL;
        connector_config.async_receive = false;
        CHECK(tcp_connector != nullptr);
        mod = tcp_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = tcpc_api->ctor(mod);
        CHECK(connector_common != nullptr);
        connector = tcpc_api->tinit(&connector_config);
        CHECK(connector != nullptr);
        CHECK(connector->get_connector_direction() == Connector::CONN_DUPLEX);
    }

    void teardown() override
    {
        tcpc_api->tterm(connector);
        tcpc_api->dtor(connector_common);
        tcp_connector->mod_dtor(mod);
        //MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST_GROUP(tcp_connector_no_tinit_tterm_call)
{
    void setup() override
    {
        // FIXIT-L workaround for CppUTest mem leak detector issue
        //MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        tcpc_api = (ConnectorApi*)tcp_connector;
        s_instance = 0;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp";
        connector_config.address = "127.0.0.1";
        connector_config.base_port = 10000;
        connector_config.setup = TcpConnectorConfig::Setup::CALL;
        connector_config.async_receive = false;
        CHECK(tcp_connector != nullptr);
        mod = tcp_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = tcpc_api->ctor(mod);
        CHECK(connector_common != nullptr);
    }

    void teardown() override
    {
        tcpc_api->tterm(connector);
        tcpc_api->dtor(connector_common);
        tcp_connector->mod_dtor(mod);
        //MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(tcp_connector_no_tinit_tterm_call, poll_undesirable)
{
    s_poll_undesirable = true;
    connector = tcpc_api->tinit(&connector_config);
    CHECK(connector != nullptr);
    size_t size = sizeof(TcpConnectorMsgHdr) + 10;
    uint8_t* message = new uint8_t[size];
    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;
    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION;
    hdr->connector_msg_length = 10;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    TcpConnector* tcpc = (TcpConnector*)connector;
    tcpc->process_receive();
    tcpc->process_receive();
    tcpc->process_receive();
    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)tcpc->receive_message(false);
    CHECK(handle == nullptr);
    delete[] message;
}

TEST(tcp_connector_no_tinit_tterm_call, poll_error)
{
    s_poll_error = true;
    connector = tcpc_api->tinit(&connector_config);
    CHECK(connector != nullptr);
    size_t size = sizeof(TcpConnectorMsgHdr) + 10;
    uint8_t* message = new uint8_t[size];
    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;
    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION;
    hdr->connector_msg_length = 10;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    TcpConnector* tcpc = (TcpConnector*)connector;
    tcpc->process_receive();
    tcpc->process_receive();
    tcpc->process_receive();
    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)tcpc->receive_message(false);
    CHECK(handle == nullptr);
    delete[] message;
}

TEST_GROUP(tcp_connector_tinit_tterm_answer)
{
    void setup() override
    {
        // FIXIT-L workaround for CppUTest mem leak detector issue
        //MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
        s_instance = 0;
        set_normal_status();
        tcpc_api = (ConnectorApi*)tcp_connector;
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp-a";
        connector_config.base_port = 20000;
        connector_config.setup = TcpConnectorConfig::Setup::ANSWER;
        connector_config.async_receive = false;
        CHECK(tcp_connector != nullptr);
        mod = tcp_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = tcpc_api->ctor(mod);
        CHECK(connector_common != nullptr);
        connector = tcpc_api->tinit(&connector_config);
        CHECK(connector->get_connector_direction() == Connector::CONN_DUPLEX);
        CHECK(connector != nullptr);
    }

    void teardown() override
    {
        tcpc_api->tterm(connector);
        tcpc_api->dtor(connector_common);
        tcp_connector->mod_dtor(mod);
        //MemoryLeakWarningPlugin::turnOnNewDeleteOverloads();
    }
};

TEST(tcp_connector_tinit_tterm_answer, null)
{
    CHECK(1==1);
}

TEST(tcp_connector_tinit_tterm_call, null)
{
    CHECK(1==1);
}

TEST(tcp_connector_tinit_tterm_thread_call, null)
{
    sleep(1);
    CHECK(1==1);
}

TEST(tcp_connector_tinit_tterm_call, alloc_discard)
{
    const uint8_t* data = nullptr;
    TcpConnector* tcpc = (TcpConnector*)connector;

    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)(tcpc->alloc_message(40,&data));
    CHECK(data != nullptr);
    CHECK(handle->connector_msg.length == 40);
    CHECK(handle->connector_msg.data == data);
    tcpc->discard_message(handle);
}

TEST(tcp_connector_tinit_tterm_call, alloc_transmit)
{
    const uint8_t* data = nullptr;
    TcpConnector* tcpc = (TcpConnector*)connector;
    set_normal_status();

    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)(tcpc->alloc_message(40,&data));
    CHECK(data != nullptr);
    CHECK(handle->connector_msg.length == 40);
    s_send_ret_other = 40;
    CHECK(handle->connector_msg.data == data);
    CHECK(tcpc->transmit_message(handle) == true);
}

TEST(tcp_connector_tinit_tterm_call, alloc_transmit_header_fail)
{
    const uint8_t* data = nullptr;
    TcpConnector* tcpc = (TcpConnector*)connector;
    set_normal_status();

    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)(tcpc->alloc_message(40,&data));
    CHECK(data != nullptr);
    CHECK(handle->connector_msg.length == 40);
    s_send_ret_header = sizeof(TcpConnectorMsgHdr)-1;
    s_send_ret_other = 40;
    CHECK(handle->connector_msg.data == data);
    CHECK(tcpc->transmit_message(handle) == false);
}

TEST(tcp_connector_tinit_tterm_call, alloc_transmit_body_fail)
{
    const uint8_t* data = nullptr;
    TcpConnector* tcpc = (TcpConnector*)connector;
    set_normal_status();

    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)(tcpc->alloc_message(40,&data));
    CHECK(data != nullptr);
    CHECK(handle->connector_msg.length == 40);
    s_send_ret_other = 30;
    CHECK(handle->connector_msg.data == data);
    CHECK(tcpc->transmit_message(handle) == false);
}

TEST(tcp_connector_tinit_tterm_call, alloc_transmit_no_sock)
{
    const uint8_t* data = nullptr;
    TcpConnector* tcpc = (TcpConnector*)connector;

    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)(tcpc->alloc_message(40,&data));
    tcpc->sock_fd = -1;
    CHECK(data != nullptr);
    CHECK(handle->connector_msg.length == 40);
    CHECK(handle->connector_msg.data == data);
    CHECK(tcpc->transmit_message(handle) == false);
}

TEST(tcp_connector_tinit_tterm_call, receive_no_sock)
{
    TcpConnector* tcpc = (TcpConnector*)connector;
    tcpc->sock_fd = -1;
    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)tcpc->receive_message(false);
    CHECK(handle == nullptr);
}

TEST(tcp_connector_tinit_tterm_call, receive)
{
    TcpConnector* tcpc = (TcpConnector*)connector;
    size_t size = sizeof(TcpConnectorMsgHdr) + 10;
    uint8_t* message = new uint8_t[size];
    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;
    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION;
    hdr->connector_msg_length = 10;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    tcpc->process_receive();
    tcpc->process_receive();
    tcpc->process_receive();
    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)tcpc->receive_message(false);
    ConnectorMsg* conn_msg = tcpc->get_connector_msg(handle);

    CHECK(handle != nullptr);
    CHECK(conn_msg->length == 10);
    CHECK(memcmp( handle->connector_msg.data, (message+sizeof(TcpConnectorMsgHdr)), 10) == 0);
    tcpc->discard_message(handle);
    delete[] message;
    handle = (TcpConnectorMsgHandle*)tcpc->receive_message(false);
    CHECK(handle == nullptr);
}

TEST(tcp_connector_no_tinit_tterm_call, receive_wrong_version)
{
    size_t size = sizeof(TcpConnectorMsgHdr) + 10;
    uint8_t* message = new uint8_t[size];
    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;
    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION+1;
    hdr->connector_msg_length = 10;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    connector = tcpc_api->tinit(&connector_config);
    CHECK(connector != nullptr);
    TcpConnector* tcpc = (TcpConnector*)connector;
    tcpc->process_receive();
    tcpc->process_receive();
    tcpc->process_receive();
    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)tcpc->receive_message(false);
    CHECK(handle == nullptr);
    delete[] message;
}

TEST(tcp_connector_no_tinit_tterm_call, receive_recv_error_EAGAIN)
{
    size_t size = sizeof(TcpConnectorMsgHdr) + 10;
    uint8_t* message = new uint8_t[size];
    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;
    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION;
    hdr->connector_msg_length = 10;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    s_rec_error = EAGAIN;
    connector = tcpc_api->tinit(&connector_config);
    CHECK(connector != nullptr);
    TcpConnector* tcpc = (TcpConnector*)connector;
    tcpc->process_receive();
    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)tcpc->receive_message(false);
    CHECK(handle != nullptr);
    tcpc->discard_message(handle);
    delete[] message;
}

TEST(tcp_connector_no_tinit_tterm_call, receive_recv_error_EBADF)
{
    size_t size = sizeof(TcpConnectorMsgHdr) + 10;
    uint8_t* message = new uint8_t[size];
    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;
    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION;
    hdr->connector_msg_length = 10;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    s_rec_error = EBADF;
    connector = tcpc_api->tinit(&connector_config);
    CHECK(connector != nullptr);
    TcpConnector* tcpc = (TcpConnector*)connector;
    tcpc->process_receive();
    tcpc->process_receive();
    tcpc->process_receive();
    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)tcpc->receive_message(false);
    CHECK(handle != nullptr);
    tcpc->discard_message(handle);
    delete[] message;
}

TEST(tcp_connector_no_tinit_tterm_call, receive_recv_closed)
{
    size_t size = sizeof(TcpConnectorMsgHdr) + 10;
    uint8_t* message = new uint8_t[size];
    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;
    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION;
    hdr->connector_msg_length = 10;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    s_rec_return_zero = true;
    connector = tcpc_api->tinit(&connector_config);
    CHECK(connector != nullptr);
    TcpConnector* tcpc = (TcpConnector*)connector;
    tcpc->process_receive();
    tcpc->process_receive();
    tcpc->process_receive();
    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)tcpc->receive_message(false);
    CHECK(handle == nullptr);
    delete[] message;
}

TEST(tcp_connector_no_tinit_tterm_call, receive_recv_body_closed)
{
    size_t size = sizeof(TcpConnectorMsgHdr) + 10;
    uint8_t* message = new uint8_t[size];
    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;
    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION;
    hdr->connector_msg_length = 10;
    s_rec_error_size = 10;  // only indicate the error on the 10 byte recv()
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    s_rec_return_zero = true;
    connector = tcpc_api->tinit(&connector_config);
    CHECK(connector != nullptr);
    TcpConnector* tcpc = (TcpConnector*)connector;
    tcpc->process_receive();
    tcpc->process_receive();
    tcpc->process_receive();
    TcpConnectorMsgHandle* handle = (TcpConnectorMsgHandle*)tcpc->receive_message(false);
    CHECK(handle == nullptr);
    delete[] message;
}

TEST_GROUP(tcp_connector_msg_handle)
{
    void setup() override
    {
    }

    void teardown() override
    {
    }
};

TEST(tcp_connector_msg_handle, test)
{
    TcpConnectorMsgHandle handle(12);
    CHECK(handle.connector_msg.length == 12);
    CHECK(handle.connector_msg.data != nullptr);
}

int main(int argc, char** argv)
{
    MemoryLeakWarningPlugin::turnOffNewDeleteOverloads();
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}
