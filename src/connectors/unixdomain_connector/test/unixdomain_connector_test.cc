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

// unixdomain_connector_test.cc author Umang Sharma <umasharm@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "connectors/unixdomain_connector/unixdomain_connector.h"
#include "connectors/unixdomain_connector/unixdomain_connector_module.h"
#include "managers/connector_manager.h"

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "main/thread_config.h"

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

using namespace snort;

extern const BaseApi* unixdomain_connector;
const ConnectorApi* unixdomainc_api = nullptr;

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

static int s_send_ret_header = sizeof(UnixDomainConnectorMsgHdr);
static int s_send_ret_other = 0;

UnixDomainConnectorConfig connector_config;

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
void ParseError(const char*, ...) { }

}

int connect (int, const struct sockaddr*, socklen_t) { return s_connect_return; }
ssize_t send (int, const void*, size_t n, int)
{
    if ( n == sizeof(UnixDomainConnectorMsgHdr) )
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
    s_send_ret_header = sizeof(UnixDomainConnectorMsgHdr);
    s_send_ret_other = 0;
    s_connect_return = 1;
    s_send_ret_header = sizeof(UnixDomainConnectorMsgHdr);
    s_send_ret_other = 0;
    s_poll_error = false;
    s_poll_undesirable = false;
    s_poll_data_available = false;
    s_rec_error = 0;
    s_rec_error_size = -1;
    s_rec_return_zero = false;
}

UnixDomainConnectorModule::UnixDomainConnectorModule() :
    Module("UnixDomainC", "UnixDomainC Help", nullptr)
{ }

ConnectorConfig::ConfigSet UnixDomainConnectorModule::get_and_clear_config()
{
    return ConnectorConfig::ConfigSet();
}

ProfileStats* UnixDomainConnectorModule::get_profile() const { return nullptr; }

bool UnixDomainConnectorModule::set(const char*, Value&, SnortConfig*) { return true; }
bool UnixDomainConnectorModule::begin(const char*, int, SnortConfig*) { return true; }
bool UnixDomainConnectorModule::end(const char*, int, SnortConfig*) { return true; }

const PegInfo* UnixDomainConnectorModule::get_pegs() const { return nullptr; }
PegCount* UnixDomainConnectorModule::get_counts() const { return nullptr; }

TEST_GROUP(unixdomain_connector)
{
    void setup() override
    {
        unixdomainc_api = (const ConnectorApi*) unixdomain_connector;
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "unixdomain";
        connector_config.paths.push_back("/tmp/pub_sub1");
        connector_config.setup = UnixDomainConnectorConfig::Setup::CALL;
        connector_config.async_receive = false;
    }

    void teardown() override
    { connector_config.paths = std::move(std::vector<std::string>()); }
};

TEST(unixdomain_connector, mod_ctor_dtor)
{
    CHECK(unixdomain_connector != nullptr);
    mod = unixdomain_connector->mod_ctor();
    CHECK(mod != nullptr);
    unixdomain_connector->mod_dtor(mod);
}

TEST(unixdomain_connector, mod_instance_ctor_dtor)
{
    CHECK(unixdomain_connector != nullptr);
    mod = unixdomain_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = unixdomainc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    unixdomainc_api->dtor(connector_common);
    unixdomain_connector->mod_dtor(mod);
}

TEST_GROUP(unixdomain_connector_call_error)
{
    void setup() override
    {
        unixdomainc_api = (const ConnectorApi*) unixdomain_connector;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "unixdomain";
        connector_config.paths.push_back("/tmp/pub_sub1");
        connector_config.setup = UnixDomainConnectorConfig::Setup::CALL;
        connector_config.async_receive = false;
        CHECK(unixdomain_connector != nullptr);
        mod = unixdomain_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = unixdomainc_api->ctor(mod);
        CHECK(connector_common != nullptr);
    }

    void teardown() override
    {
        connector = unixdomainc_api->tinit(connector_config);
        CHECK(connector == nullptr);
        unixdomainc_api->dtor(connector_common);
        unixdomain_connector->mod_dtor(mod);
        connector_config.paths = std::move(std::vector<std::string>());
    }
};

TEST_GROUP(unixdomain_connector_call_other)
{
    void teardown()
    { connector_config.paths = std::move(std::vector<std::string>()); }
};

TEST_GROUP(unixdomain_connector_answer_error)
{
    void setup() override
    {
        unixdomainc_api = (const ConnectorApi*) unixdomain_connector;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "unixdomain-a";
        connector_config.paths.push_back("/tmp/pub_sub1");
        connector_config.setup = UnixDomainConnectorConfig::Setup::ANSWER;
        connector_config.async_receive = false;
        CHECK(unixdomain_connector != nullptr);
        mod = unixdomain_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = unixdomainc_api->ctor(mod);
        CHECK(connector_common != nullptr);
    }

    void teardown() override
    {
        connector = unixdomainc_api->tinit(connector_config);
        CHECK(connector == nullptr);
        unixdomainc_api->dtor(connector_common);
        unixdomain_connector->mod_dtor(mod);
        connector_config.paths = std::move(std::vector<std::string>());
    }
};

TEST(unixdomain_connector_call_error, bad_socket)
{
    s_socket_return = -1;
}

TEST(unixdomain_connector_call_error, bad_connect)
{
    s_connect_return = -1;
}

TEST(unixdomain_connector_answer_error, bad_socket)
{
    s_socket_return = -1;
}

TEST(unixdomain_connector_answer_error, bad_bind)
{
    s_bind_return = -1;
}

TEST(unixdomain_connector_answer_error, bad_listen)
{
    s_listen_return = -1;
}

TEST(unixdomain_connector_answer_error, bad_accept)
{
    s_accept_return = -1;
}

TEST(unixdomain_connector_call_other, bad_setup)
{
    unixdomainc_api = (const ConnectorApi*) unixdomain_connector;
    s_instance = 0;
    set_normal_status();
    connector_config.direction = Connector::CONN_DUPLEX;
    connector_config.connector_name = "unixdomain";
    connector_config.paths.push_back("/tmp/pub_sub1");
    connector_config.setup = (UnixDomainConnectorConfig::Setup)(-1);
    connector_config.async_receive = false;
    CHECK(unixdomain_connector != nullptr);
    mod = unixdomain_connector->mod_ctor();
    CHECK(mod != nullptr);
    connector_common = unixdomainc_api->ctor(mod);
    CHECK(connector_common != nullptr);
    connector = unixdomainc_api->tinit(connector_config);
    CHECK(connector == nullptr);
    unixdomainc_api->dtor(connector_common);
    unixdomain_connector->mod_dtor(mod);
}

TEST_GROUP(unixdomain_connector_tinit_tterm_thread_call)
{
    void setup() override
    {
        unixdomainc_api = (const ConnectorApi*) unixdomain_connector;
        s_instance = 0;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "unixdomain";
        connector_config.paths.push_back("/tmp/pub_sub1");
        connector_config.setup = UnixDomainConnectorConfig::Setup::CALL;
        connector_config.async_receive = true;
        CHECK(unixdomain_connector != nullptr);
        mod = unixdomain_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = unixdomainc_api->ctor(mod);
        CHECK(connector_common != nullptr);
        connector = unixdomainc_api->tinit(connector_config);
        CHECK(connector != nullptr);
        CHECK(connector->get_connector_direction() == Connector::CONN_DUPLEX);
    }

    void teardown() override
    {
        unixdomainc_api->tterm(connector);
        unixdomainc_api->dtor(connector_common);
        unixdomain_connector->mod_dtor(mod);
        connector_config.paths = std::move(std::vector<std::string>());
    }
};

TEST_GROUP(unixdomain_connector_tinit_tterm_call)
{
    void setup() override
    {
        unixdomainc_api = (const ConnectorApi*) unixdomain_connector;
        s_instance = 0;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "unixdomain";
        connector_config.paths.push_back("/tmp/pub_sub1");
        connector_config.setup = UnixDomainConnectorConfig::Setup::CALL;
        connector_config.async_receive = false;
        CHECK(unixdomain_connector != nullptr);
        mod = unixdomain_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = unixdomainc_api->ctor(mod);
        CHECK(connector_common != nullptr);
        connector = unixdomainc_api->tinit(connector_config);
        CHECK(connector != nullptr);
        CHECK(connector->get_connector_direction() == Connector::CONN_DUPLEX);
    }

    void teardown() override
    {
        unixdomainc_api->tterm(connector);
        unixdomainc_api->dtor(connector_common);
        unixdomain_connector->mod_dtor(mod);
        connector_config.paths = std::move(std::vector<std::string>());
    }
};

TEST_GROUP(unixdomain_connector_no_tinit_tterm_call)
{
    void setup() override
    {
        unixdomainc_api = (const ConnectorApi*) unixdomain_connector;
        s_instance = 0;
        set_normal_status();
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "unixdomain";
        connector_config.paths.push_back("/tmp/pub_sub1");
        connector_config.setup = UnixDomainConnectorConfig::Setup::CALL;
        connector_config.async_receive = false;
        CHECK(unixdomain_connector != nullptr);
        mod = unixdomain_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = unixdomainc_api->ctor(mod);
        CHECK(connector_common != nullptr);
    }

    void teardown() override
    {
        unixdomainc_api->tterm(connector);
        unixdomainc_api->dtor(connector_common);
        unixdomain_connector->mod_dtor(mod);
        connector_config.paths = std::move(std::vector<std::string>());
    }
};

TEST(unixdomain_connector_no_tinit_tterm_call, poll_error)
{
    s_poll_error = true;
    connector = unixdomainc_api->tinit(connector_config);
    CHECK(connector != nullptr);
    size_t size = sizeof(UnixDomainConnectorMsgHdr) + 10;
    uint8_t* message = new uint8_t[size];
    for (int i = sizeof(UnixDomainConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;
    UnixDomainConnectorMsgHdr* hdr = (UnixDomainConnectorMsgHdr*)message;
    hdr->version = UNIXDOMAIN_FORMAT_VERSION;
    hdr->connector_msg_length = 10;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    UnixDomainConnector* unixdomainc = (UnixDomainConnector*)connector;

    unixdomainc->process_receive();
    unixdomainc->process_receive();
    unixdomainc->process_receive();

    const ConnectorMsg msg = unixdomainc->receive_message(false);
    CHECK(msg.get_data() == nullptr);
    CHECK(msg.get_length() == 0);

    delete[] message;
}

TEST_GROUP(unixdomain_connector_tinit_tterm_answer)
{
    void setup() override
    {
        s_instance = 0;
        set_normal_status();
        unixdomainc_api = (const ConnectorApi*) unixdomain_connector;
        connector_config.direction = Connector::CONN_DUPLEX;
        connector_config.connector_name = "unixdomain-a";
        connector_config.paths.push_back("/tmp/pub_sub2");
        connector_config.setup = UnixDomainConnectorConfig::Setup::ANSWER;
        connector_config.async_receive = false;
        CHECK(unixdomain_connector != nullptr);
        mod = unixdomain_connector->mod_ctor();
        CHECK(mod != nullptr);
        connector_common = unixdomainc_api->ctor(mod);
        CHECK(connector_common != nullptr);
        connector = unixdomainc_api->tinit(connector_config);
        CHECK(connector->get_connector_direction() == Connector::CONN_DUPLEX);
        CHECK(connector != nullptr);
    }

    void teardown() override
    {
        unixdomainc_api->tterm(connector);
        unixdomainc_api->dtor(connector_common);
        unixdomain_connector->mod_dtor(mod);
        connector_config.paths = std::move(std::vector<std::string>());
    }
};

TEST(unixdomain_connector_tinit_tterm_call, alloc_transmit)
{
    const uint32_t len = 40;
    const uint8_t* data = new uint8_t[len];
    UnixDomainConnector* unixdomainc = (UnixDomainConnector*)connector;
    set_normal_status();

    ConnectorMsg msg(data, len, true);

    CHECK(msg.get_length() == len);
    CHECK(msg.get_data() == data);

    s_send_ret_other = len;
    CHECK(unixdomainc->transmit_message(msg) == true);
    CHECK(unixdomainc->transmit_message(std::move(msg)) == true);
}

TEST(unixdomain_connector_tinit_tterm_call, alloc_transmit_header_fail)
{
    const uint32_t len = 40;
    const uint8_t* data = new uint8_t[len];
    UnixDomainConnector* unixdomainc = (UnixDomainConnector*)connector;
    set_normal_status();

    ConnectorMsg msg(data, len, true);

    CHECK(msg.get_length() == len);
    CHECK(msg.get_data() == data);

    s_send_ret_header = sizeof(UnixDomainConnectorMsgHdr)-1;
    s_send_ret_other = len;
    CHECK(unixdomainc->transmit_message(msg) == false);
    CHECK(unixdomainc->transmit_message(std::move(msg)) == false);
}

TEST(unixdomain_connector_tinit_tterm_call, alloc_transmit_body_fail)
{
    const uint32_t len = 40;
    const uint8_t* data = new uint8_t[len];
    UnixDomainConnector* unixdomainc = (UnixDomainConnector*)connector;
    set_normal_status();

    ConnectorMsg msg(data, len, true);

    CHECK(msg.get_length() == len);
    CHECK(msg.get_data() == data);

    s_send_ret_other = 30;
    CHECK(unixdomainc->transmit_message(msg) == false);
    CHECK(unixdomainc->transmit_message(std::move(msg)) == false);
}

TEST(unixdomain_connector_tinit_tterm_call, alloc_transmit_no_sock)
{
    const uint32_t len = 40;
    const uint8_t* data = new uint8_t[len];
    UnixDomainConnector* unixdomainc = (UnixDomainConnector*)connector;

    ConnectorMsg msg(data, len, true);

    CHECK(msg.get_length() == len);
    CHECK(msg.get_data() == data);

    unixdomainc->sock_fd = -1;
    CHECK(unixdomainc->transmit_message(msg) == false);
    CHECK(unixdomainc->transmit_message(std::move(msg)) == false);
}

TEST(unixdomain_connector_tinit_tterm_call, receive_no_sock)
{
    UnixDomainConnector* unixdomainc = (UnixDomainConnector*)connector;
    unixdomainc->sock_fd = -1;
    const ConnectorMsg msg = unixdomainc->receive_message(false);
    CHECK(msg.get_data() == nullptr);
    CHECK(msg.get_length() == 0);
}

TEST(unixdomain_connector_tinit_tterm_call, receive)
{
    const uint32_t cmsg_len = 10;
    UnixDomainConnector* unixdomainc = (UnixDomainConnector*)connector;
    size_t size = sizeof(UnixDomainConnectorMsgHdr) + cmsg_len;
    uint8_t* message = new uint8_t[size];

    for (int i = sizeof(UnixDomainConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;

    UnixDomainConnectorMsgHdr* hdr = (UnixDomainConnectorMsgHdr*)message;
    hdr->version = UNIXDOMAIN_FORMAT_VERSION;
    hdr->connector_msg_length = cmsg_len;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;

    unixdomainc->process_receive();
    unixdomainc->process_receive();
    unixdomainc->process_receive();
    ConnectorMsg conn_msg = unixdomainc->receive_message(false);

    CHECK(conn_msg.get_length() == cmsg_len);
    CHECK(memcmp(conn_msg.get_data(), (message+sizeof(UnixDomainConnectorMsgHdr)), cmsg_len) == 0);

    delete[] message;

    conn_msg = std::move(unixdomainc->receive_message(false));
    CHECK(conn_msg.get_data() == nullptr);
    CHECK(conn_msg.get_length() == 0);
}

TEST(unixdomain_connector_no_tinit_tterm_call, receive_wrong_version)
{
    const uint32_t cmsg_len = 10;
    size_t size = sizeof(UnixDomainConnectorMsgHdr) + cmsg_len;
    uint8_t* message = new uint8_t[size];

    for (int i = sizeof(UnixDomainConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;

    UnixDomainConnectorMsgHdr* hdr = (UnixDomainConnectorMsgHdr*)message;
    hdr->version = UNIXDOMAIN_FORMAT_VERSION+1;
    hdr->connector_msg_length = cmsg_len;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    connector = unixdomainc_api->tinit(connector_config);
    CHECK(connector != nullptr);
    UnixDomainConnector* unixdomainc = (UnixDomainConnector*)connector;

    unixdomainc->process_receive();
    unixdomainc->process_receive();
    unixdomainc->process_receive();
    const ConnectorMsg conn_msg = unixdomainc->receive_message(false);

    CHECK(conn_msg.get_data() == nullptr);
    CHECK(conn_msg.get_length() == 0);
    delete[] message;
}

TEST(unixdomain_connector_no_tinit_tterm_call, receive_recv_error_EAGAIN)
{
    const uint32_t cmsg_len = 10;
    size_t size = sizeof(UnixDomainConnectorMsgHdr) + cmsg_len;
    uint8_t* message = new uint8_t[size];

    for (int i = sizeof(UnixDomainConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;

    UnixDomainConnectorMsgHdr* hdr = (UnixDomainConnectorMsgHdr*)message;
    hdr->version = UNIXDOMAIN_FORMAT_VERSION;
    hdr->connector_msg_length = cmsg_len;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    s_rec_error = EAGAIN;

    connector = unixdomainc_api->tinit(connector_config);
    CHECK(connector != nullptr);
    UnixDomainConnector* unixdomainc = (UnixDomainConnector*)connector;

    unixdomainc->process_receive();
    const ConnectorMsg conn_msg = unixdomainc->receive_message(false);

    CHECK(conn_msg.get_length() == cmsg_len);
    CHECK(memcmp(conn_msg.get_data(), (message+sizeof(UnixDomainConnectorMsgHdr)), cmsg_len) == 0);

    delete[] message;
}

TEST(unixdomain_connector_no_tinit_tterm_call, receive_recv_error_EBADF)
{
    const uint32_t cmsg_len = 10;
    size_t size = sizeof(UnixDomainConnectorMsgHdr) + cmsg_len;
    uint8_t* message = new uint8_t[size];

    for (int i = sizeof(UnixDomainConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;

    UnixDomainConnectorMsgHdr* hdr = (UnixDomainConnectorMsgHdr*)message;
    hdr->version = UNIXDOMAIN_FORMAT_VERSION;
    hdr->connector_msg_length = cmsg_len;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    s_rec_error = EBADF;

    connector = unixdomainc_api->tinit(connector_config);
    CHECK(connector != nullptr);
    UnixDomainConnector* unixdomainc = (UnixDomainConnector*)connector;

    unixdomainc->process_receive();
    unixdomainc->process_receive();
    unixdomainc->process_receive();
    const ConnectorMsg conn_msg = unixdomainc->receive_message(false);

    CHECK(conn_msg.get_length() == cmsg_len);
    CHECK(memcmp(conn_msg.get_data(), (message+sizeof(UnixDomainConnectorMsgHdr)), cmsg_len) == 0);

    delete[] message;
}

TEST(unixdomain_connector_no_tinit_tterm_call, receive_recv_closed)
{
    const uint32_t cmsg_len = 10;
    size_t size = sizeof(UnixDomainConnectorMsgHdr) + cmsg_len;
    uint8_t* message = new uint8_t[size];

    for (int i = sizeof(UnixDomainConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;

    UnixDomainConnectorMsgHdr* hdr = (UnixDomainConnectorMsgHdr*)message;
    hdr->version = UNIXDOMAIN_FORMAT_VERSION;
    hdr->connector_msg_length = cmsg_len;
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    s_rec_return_zero = true;

    connector = unixdomainc_api->tinit(connector_config);
    CHECK(connector != nullptr);
    UnixDomainConnector* unixdomainc = (UnixDomainConnector*)connector;

    unixdomainc->process_receive();
    unixdomainc->process_receive();
    unixdomainc->process_receive();
    const ConnectorMsg conn_msg = unixdomainc->receive_message(false);

    CHECK(conn_msg.get_data() == nullptr);
    CHECK(conn_msg.get_length() == 0);

    delete[] message;
}

TEST(unixdomain_connector_no_tinit_tterm_call, receive_recv_body_closed)
{
    const uint32_t cmsg_len = 10;
    size_t size = sizeof(UnixDomainConnectorMsgHdr) + cmsg_len;
    uint8_t* message = new uint8_t[size];

    for (int i = sizeof(UnixDomainConnectorMsgHdr); i < (int)size; i++ )
        message[i] = i;

    UnixDomainConnectorMsgHdr* hdr = (UnixDomainConnectorMsgHdr*)message;
    hdr->version = UNIXDOMAIN_FORMAT_VERSION;
    hdr->connector_msg_length = cmsg_len;
    s_rec_error_size = cmsg_len;  // only indicate the error on the cmsg_len byte recv()
    s_rec_message = message;
    s_rec_message_size = size; // also trigger the read action
    s_poll_data_available = true;
    s_rec_return_zero = true;

    connector = unixdomainc_api->tinit(connector_config);
    CHECK(connector != nullptr);
    UnixDomainConnector* unixdomainc = (UnixDomainConnector*)connector;

    unixdomainc->process_receive();
    unixdomainc->process_receive();
    unixdomainc->process_receive();
    const ConnectorMsg conn_msg = unixdomainc->receive_message(false);

    CHECK(conn_msg.get_data() == nullptr);
    CHECK(conn_msg.get_length() == 0);

    delete[] message;
}

int main(int argc, char** argv)
{
    int return_value = CommandLineTestRunner::RunAllTests(argc, argv);
    return return_value;
}
