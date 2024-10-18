//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "main/thread_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

extern const BaseApi* tcp_connector;
const ConnectorApi* tcpc_api = nullptr;

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
void show_stats(PegCount*, const PegInfo*, const std::vector<unsigned>&, const char*, FILE*) { }

namespace snort
{
unsigned get_instance_id()
{ return s_instance; }
unsigned ThreadConfig::get_instance_max() { return 1; }

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

    fds[0].revents = 0;
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

#ifdef __GLIBC__
int socket (int, int, int) __THROW { return s_socket_return; }
int bind (int, const struct sockaddr*, socklen_t) __THROW { return s_bind_return; }
int listen (int, int) __THROW { return s_listen_return; }
#else
int socket (int, int, int) { return s_socket_return; }
int bind (int, const struct sockaddr*, socklen_t) { return s_bind_return; }
int listen (int, int) { return s_listen_return; }
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
{ config_set = nullptr; }

TcpConnectorConfig::TcpConnectorConfigSet* TcpConnectorModule::get_and_clear_config()
{
    return new TcpConnectorConfig::TcpConnectorConfigSet;
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
        tcpc_api = (const ConnectorApi*) tcp_connector;
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp";
        connector_config.address = "127.0.0.1";
        connector_config.ports.push_back("10000");
        connector_config.setup = TcpConnectorConfig::Setup::CALL;
        connector_config.async_receive = false;
    }

    void teardown() override
    { connector_config.ports = std::move(std::vector<std::string>()); }
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
        tcpc_api = (const ConnectorApi*) tcp_connector;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp";
        connector_config.address = "127.0.0.1";
        connector_config.ports.push_back("10000");
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
        connector = tcpc_api->tinit(connector_config);
        CHECK(connector == nullptr);
        tcpc_api->dtor(connector_common);
        tcp_connector->mod_dtor(mod);
        connector_config.ports = std::move(std::vector<std::string>());
    }
};

TEST_GROUP(tcp_connector_call_other)
{
    void teardown()
    { connector_config.ports = std::move(std::vector<std::string>()); }
};

TEST_GROUP(tcp_connector_answer_error)
{
    void setup() override
    {
        tcpc_api = (const ConnectorApi*) tcp_connector;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp-a";
        connector_config.ports.push_back("20000");
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
        connector = tcpc_api->tinit(connector_config);
        CHECK(connector == nullptr);
        tcpc_api->dtor(connector_common);
        tcp_connector->mod_dtor(mod);
        connector_config.ports = std::move(std::vector<std::string>());
    }
};

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
    tcpc_api = (const ConnectorApi*) tcp_connector;
    s_instance = 0;
    set_normal_status();
    connector_config.direction = Connector::CONN_DUPLEX;
    connector_config.connector_name = "tcp";
    connector_config.address = "127.0.0.1";
    connector_config.ports.push_back("10000");
    connector_config.setup = (TcpConnectorConfig::Setup)(-1);
    connector_config.async_receive = false;
    CHECK(tcp_connector != nullptr);
    mod = tcp_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = tcpc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    connector = tcpc_api->tinit(connector_config);
    CHECK(connector == nullptr);
    tcpc_api->dtor(connector_common);
    tcp_connector->mod_dtor(mod);
}

TEST_GROUP(tcp_connector_tinit_tterm_thread_call)
{
    void setup() override
    {
        tcpc_api = (const ConnectorApi*) tcp_connector;
        s_instance = 0;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp";
        connector_config.address = "127.0.0.1";
        connector_config.ports.push_back("10000");
        connector_config.setup = TcpConnectorConfig::Setup::CALL;
        connector_config.async_receive = true;
        CHECK(tcp_connector != nullptr);
        mod = tcp_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = tcpc_api->ctor(mod);
        CHECK(connector_common != nullptr);
        connector = tcpc_api->tinit(connector_config);
        CHECK(connector != nullptr);
        CHECK(connector->get_connector_direction() == Connector::CONN_DUPLEX);
    }

    void teardown() override
    {
        tcpc_api->tterm(connector);
        tcpc_api->dtor(connector_common);
        tcp_connector->mod_dtor(mod);
        connector_config.ports = std::move(std::vector<std::string>());
    }
};

TEST_GROUP(tcp_connector_tinit_tterm_call)
{
    void setup() override
    {
        tcpc_api = (const ConnectorApi*) tcp_connector;
        s_instance = 0;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp";
        connector_config.address = "127.0.0.1";
        connector_config.ports.push_back("10000");
        connector_config.setup = TcpConnectorConfig::Setup::CALL;
        connector_config.async_receive = false;
        CHECK(tcp_connector != nullptr);
        mod = tcp_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = tcpc_api->ctor(mod);
        CHECK(connector_common != nullptr);
        connector = tcpc_api->tinit(connector_config);
        CHECK(connector != nullptr);
        CHECK(connector->get_connector_direction() == Connector::CONN_DUPLEX);
    }

    void teardown() override
    {
        tcpc_api->tterm(connector);
        tcpc_api->dtor(connector_common);
        tcp_connector->mod_dtor(mod);
        connector_config.ports = std::move(std::vector<std::string>());
    }
};

TEST_GROUP(tcp_connector_no_tinit_tterm_call)
{
    void setup() override
    {
        tcpc_api = (const ConnectorApi*) tcp_connector;
        s_instance = 0;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp";
        connector_config.address = "127.0.0.1";
        connector_config.ports.push_back("10000");
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
        connector_config.ports = std::move(std::vector<std::string>());
    }
};

TEST(tcp_connector_no_tinit_tterm_call, poll_undesirable)
{
    s_poll_undesirable = true;
    connector = tcpc_api->tinit(connector_config);
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

    const ConnectorMsg msg = tcpc->receive_message(false);
    CHECK(msg.get_data() == nullptr);
    CHECK(msg.get_length() == 0);

    delete[] message;
}

TEST(tcp_connector_no_tinit_tterm_call, poll_error)
{
    s_poll_error = true;
    connector = tcpc_api->tinit(connector_config);
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

    const ConnectorMsg msg = tcpc->receive_message(false);
    CHECK(msg.get_data() == nullptr);
    CHECK(msg.get_length() == 0);

    delete[] message;
}

TEST_GROUP(tcp_connector_tinit_tterm_answer)
{
    void setup() override
    {
        s_instance = 0;
        set_normal_status();
        tcpc_api = (const ConnectorApi*) tcp_connector;
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "tcp-a";
        connector_config.ports.push_back("20000");
        connector_config.setup = TcpConnectorConfig::Setup::ANSWER;
        connector_config.async_receive = false;
        CHECK(tcp_connector != nullptr);
        mod = tcp_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = tcpc_api->ctor(mod);
        CHECK(connector_common != nullptr);
        connector = tcpc_api->tinit(connector_config);
        CHECK(connector->get_connector_direction() == Connector::CONN_DUPLEX);
        CHECK(connector != nullptr);
    }

    void teardown() override
    {
        tcpc_api->tterm(connector);
        tcpc_api->dtor(connector_common);
        tcp_connector->mod_dtor(mod);
        connector_config.ports = std::move(std::vector<std::string>());
    }
};

TEST(tcp_connector_tinit_tterm_call, alloc_transmit)
{
    const uint32_t len = 40;
    const uint8_t* data = new uint8_t[len];
    TcpConnector* tcpc = (TcpConnector*)connector;
    set_normal_status();

    ConnectorMsg msg(data, len, true);

    CHECK(msg.get_length() == len);
    CHECK(msg.get_data() == data);

    s_send_ret_other = len;
    CHECK(tcpc->transmit_message(msg) == true);
    CHECK(tcpc->transmit_message(std::move(msg)) == true);
}

TEST(tcp_connector_tinit_tterm_call, alloc_transmit_header_fail)
{
    const uint32_t len = 40;
    const uint8_t* data = new uint8_t[len];
    TcpConnector* tcpc = (TcpConnector*)connector;
    set_normal_status();

    ConnectorMsg msg(data, len, true);

    CHECK(msg.get_length() == len);
    CHECK(msg.get_data() == data);

    s_send_ret_header = sizeof(TcpConnectorMsgHdr)-1;
    s_send_ret_other = len;
    CHECK(tcpc->transmit_message(msg) == false);
    CHECK(tcpc->transmit_message(std::move(msg)) == false);
}

TEST(tcp_connector_tinit_tterm_call, alloc_transmit_body_fail)
{
    const uint32_t len = 40;
    const uint8_t* data = new uint8_t[len];
    TcpConnector* tcpc = (TcpConnector*)connector;
    set_normal_status();

    ConnectorMsg msg(data, len, true);

    CHECK(msg.get_length() == len);
    CHECK(msg.get_data() == data);

    s_send_ret_other = 30;
    CHECK(tcpc->transmit_message(msg) == false);
    CHECK(tcpc->transmit_message(std::move(msg)) == false);
}

TEST(tcp_connector_tinit_tterm_call, alloc_transmit_no_sock)
{
    const uint32_t len = 40;
    const uint8_t* data = new uint8_t[len];
    TcpConnector* tcpc = (TcpConnector*)connector;

    ConnectorMsg msg(data, len, true);

    CHECK(msg.get_length() == len);
    CHECK(msg.get_data() == data);

    tcpc->sock_fd = -1;
    CHECK(tcpc->transmit_message(msg) == false);
    CHECK(tcpc->transmit_message(std::move(msg)) == false);
}

TEST(tcp_connector_tinit_tterm_call, receive_no_sock)
{
    TcpConnector* tcpc = (TcpConnector*)connector;
    tcpc->sock_fd = -1;
    const ConnectorMsg msg = tcpc->receive_message(false);
    CHECK(msg.get_data() == nullptr);
    CHECK(msg.get_length() == 0);
}

TEST(tcp_connector_tinit_tterm_call, receive)
{
    const uint32_t cmsg_len = 10;
    TcpConnector* tcpc = (TcpConnector*)connector;
    size_t size = sizeof(TcpConnectorMsgHdr) + cmsg_len;
    uint8_t* message = new uint8_t[size];

    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;

    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION;
    hdr->connector_msg_length = cmsg_len;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;

    tcpc->process_receive();
    tcpc->process_receive();
    tcpc->process_receive();
    ConnectorMsg conn_msg = tcpc->receive_message(false);

    CHECK(conn_msg.get_length() == cmsg_len);
    CHECK(memcmp(conn_msg.get_data(), (message+sizeof(TcpConnectorMsgHdr)), cmsg_len) == 0);

    delete[] message;

    conn_msg = std::move(tcpc->receive_message(false));
    CHECK(conn_msg.get_data() == nullptr);
    CHECK(conn_msg.get_length() == 0);
}

TEST(tcp_connector_no_tinit_tterm_call, receive_wrong_version)
{
    const uint32_t cmsg_len = 10;
    size_t size = sizeof(TcpConnectorMsgHdr) + cmsg_len;
    uint8_t* message = new uint8_t[size];

    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;

    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION+1;
    hdr->connector_msg_length = cmsg_len;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    connector = tcpc_api->tinit(connector_config);
    CHECK(connector != nullptr);
    TcpConnector* tcpc = (TcpConnector*)connector;

    tcpc->process_receive();
    tcpc->process_receive();
    tcpc->process_receive();
    const ConnectorMsg conn_msg = tcpc->receive_message(false);

    CHECK(conn_msg.get_data() == nullptr);
    CHECK(conn_msg.get_length() == 0);
    delete[] message;
}

TEST(tcp_connector_no_tinit_tterm_call, receive_recv_error_EAGAIN)
{
    const uint32_t cmsg_len = 10;
    size_t size = sizeof(TcpConnectorMsgHdr) + cmsg_len;
    uint8_t* message = new uint8_t[size];

    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;

    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION;
    hdr->connector_msg_length = cmsg_len;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    s_rec_error = EAGAIN;

    connector = tcpc_api->tinit(connector_config);
    CHECK(connector != nullptr);
    TcpConnector* tcpc = (TcpConnector*)connector;

    tcpc->process_receive();
    const ConnectorMsg conn_msg = tcpc->receive_message(false);

    CHECK(conn_msg.get_length() == cmsg_len);
    CHECK(memcmp(conn_msg.get_data(), (message+sizeof(TcpConnectorMsgHdr)), cmsg_len) == 0);

    delete[] message;
}

TEST(tcp_connector_no_tinit_tterm_call, receive_recv_error_EBADF)
{
    const uint32_t cmsg_len = 10;
    size_t size = sizeof(TcpConnectorMsgHdr) + cmsg_len;
    uint8_t* message = new uint8_t[size];

    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;

    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION;
    hdr->connector_msg_length = cmsg_len;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    s_rec_error = EBADF;

    connector = tcpc_api->tinit(connector_config);
    CHECK(connector != nullptr);
    TcpConnector* tcpc = (TcpConnector*)connector;

    tcpc->process_receive();
    tcpc->process_receive();
    tcpc->process_receive();
    const ConnectorMsg conn_msg = tcpc->receive_message(false);

    CHECK(conn_msg.get_length() == cmsg_len);
    CHECK(memcmp(conn_msg.get_data(), (message+sizeof(TcpConnectorMsgHdr)), cmsg_len) == 0);

    delete[] message;
}

TEST(tcp_connector_no_tinit_tterm_call, receive_recv_closed)
{
    const uint32_t cmsg_len = 10;
    size_t size = sizeof(TcpConnectorMsgHdr) + cmsg_len;
    uint8_t* message = new uint8_t[size];

    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;

    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION;
    hdr->connector_msg_length = cmsg_len;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    s_rec_return_zero = true;

    connector = tcpc_api->tinit(connector_config);
    CHECK(connector != nullptr);
    TcpConnector* tcpc = (TcpConnector*)connector;

    tcpc->process_receive();
    tcpc->process_receive();
    tcpc->process_receive();
    const ConnectorMsg conn_msg = tcpc->receive_message(false);

    CHECK(conn_msg.get_data() == nullptr);
    CHECK(conn_msg.get_length() == 0);

    delete[] message;
}

TEST(tcp_connector_no_tinit_tterm_call, receive_recv_body_closed)
{
    const uint32_t cmsg_len = 10;
    size_t size = sizeof(TcpConnectorMsgHdr) + cmsg_len;
    uint8_t* message = new uint8_t[size];

    for (int i = sizeof(TcpConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;

    TcpConnectorMsgHdr* hdr = (TcpConnectorMsgHdr*)message;
    hdr->version = TCP_FORMAT_VERSION;
    hdr->connector_msg_length = cmsg_len;
    s_rec_error_size = cmsg_len;  // only indicate the error on the cmsg_len byte recv()
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    s_rec_return_zero = true;

    connector = tcpc_api->tinit(connector_config);
    CHECK(connector != nullptr);
    TcpConnector* tcpc = (TcpConnector*)connector;

    tcpc->process_receive();
    tcpc->process_receive();
    tcpc->process_receive();
    const ConnectorMsg conn_msg = tcpc->receive_message(false);

    CHECK(conn_msg.get_data() == nullptr);
    CHECK(conn_msg.get_length() == 0);

    delete[] message;
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}
