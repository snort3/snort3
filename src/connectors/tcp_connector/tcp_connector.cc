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

// tcp_connector.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_connector.h"

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log/messages.h"
#include "profiler/profiler_defs.h"

#include "tcp_connector_module.h"

using namespace snort;

/* Globals ****************************************************************/

THREAD_LOCAL SimpleStats tcp_connector_stats;
THREAD_LOCAL ProfileStats tcp_connector_perfstats;

enum ReadDataOutcome { SUCCESS = 0, TRUNCATED, ERROR, CLOSED, PARTIAL, AGAIN };

static ReadDataOutcome read_data(int sockfd, uint8_t *data, uint16_t length, ssize_t& read_offset)
{
    ssize_t bytes_read, offset;

    offset = read_offset;
    bytes_read = recv(sockfd, data + offset, length - offset, 0);
    if (bytes_read == 0)
    {
        if ( offset != 0 )
            return TRUNCATED;
        return CLOSED;
    }
    if ( bytes_read == -1 )
    {
        if (errno == EAGAIN || errno == EINTR)
        {
            if (offset > 0)
                return PARTIAL;
            return AGAIN;
        }
        return ERROR;
    }
    read_offset = offset + bytes_read;
    if ((offset + bytes_read) < length)
        return PARTIAL;

    return SUCCESS;
}

static ReadDataOutcome read_message_data(int sockfd, uint16_t length, uint8_t *data)
{
    if ( length > 0 )
    {
        ReadDataOutcome rval;
        do
        {
            ssize_t offset = 0;
            rval = read_data(sockfd, data, length, offset);
        } while (rval == PARTIAL || rval == AGAIN);

        if (rval != SUCCESS)
            return rval;
    }

    return SUCCESS;
}


ConnectorMsg* TcpConnector::read_message()
{
    TcpConnectorMsgHdr hdr;
    ReadDataOutcome outcome;

    outcome = read_message_data(sock_fd, sizeof(hdr), (uint8_t*)&hdr);
    if (outcome != SUCCESS)
    {
        if (outcome == CLOSED)
            LogMessage("TcpC Input Thread: Connection closed\n");
        else
            ErrorMessage("TcpC Input Thread: Unable to receive message header: %d\n", (int)outcome);
        return nullptr;
    }

    if (hdr.version != TCP_FORMAT_VERSION)
    {
        ErrorMessage("TcpC Input Thread: Received header with invalid version 0x%d\n", (int)hdr.version);
        return nullptr;
    }

    uint8_t* data = new uint8_t[hdr.connector_msg_length];

    if ((outcome = read_message_data(sock_fd, hdr.connector_msg_length, data)) != SUCCESS)
    {
        if (outcome == CLOSED)
            LogMessage("TcpC Input Thread: Connection closed while reading message data");
        else
            ErrorMessage("TcpC Input Thread: Unable to receive local message data: %d\n", (int)outcome);
        delete[] data;
        return nullptr;
    }

    return new ConnectorMsg(data, hdr.connector_msg_length, true);
}

void TcpConnector::process_receive()
{
    struct pollfd pfds[1];
    int rval;

    pfds[0].events = POLLIN;
    pfds[0].fd = sock_fd;
    rval = poll(pfds, 1, 1000);
    if (rval == -1)
    {
        if (errno != EINTR)
        {

            char error_msg[1024] = { '\0' };
            if (strerror_r(errno, error_msg, sizeof(error_msg)) == 0)
                ErrorMessage("TcpC Input Thread: Error polling on socket %d: %s\n", pfds[0].fd, error_msg);
            else
                ErrorMessage("TcpC Input Thread: Error polling on socket %d: (%d)\n", pfds[0].fd, errno);
        }
        return;
    }
    else if ((pfds[0].revents & (POLLHUP|POLLERR|POLLNVAL)) != 0)
    {
        ErrorMessage("TcpC Input Thread: Undesirable return event while polling on socket %d: 0x%x\n",
                pfds[0].fd, pfds[0].revents);
        return;
    }
    else if (rval > 0 && pfds[0].revents & POLLIN)
    {
        ConnectorMsg* connector_msg = read_message();
        if (connector_msg && !receive_ring->put(connector_msg))
        {
            ErrorMessage("TcpC Input Thread: overrun\n");
            delete connector_msg;
        }
    }
}

void TcpConnector::receive_processing_thread()
{
    while (run_thread.load(std::memory_order_relaxed))
    {
        process_receive();
    }
}

void TcpConnector::start_receive_thread()
{
    run_thread.store(true, std::memory_order_relaxed);
    receive_thread = new std::thread(&TcpConnector::receive_processing_thread, this);
}

void TcpConnector::stop_receive_thread()
{
    if ( receive_thread != nullptr )
    {
        run_thread.store(false, std::memory_order_relaxed);
        receive_thread->join();
        delete receive_thread;
    }
}

TcpConnector::TcpConnector(const TcpConnectorConfig& tcp_connector_config, int sfd) :
    Connector(tcp_connector_config), sock_fd(sfd), run_thread(false), receive_thread(nullptr),
    receive_ring(new ReceiveRing(50))
{
    if ( tcp_connector_config.async_receive )
        start_receive_thread();
}

TcpConnector::~TcpConnector()
{
    stop_receive_thread();
    delete receive_ring;
    close(sock_fd);
}

bool TcpConnector::internal_transmit_message(const ConnectorMsg& msg)
{
    if ( !msg.get_data() or msg.get_length() == 0 )
        return false;

    if ( sock_fd < 0 )
    {
        ErrorMessage("TcpConnector: transmitting to a closed socket\n");
        return false;
    }

    TcpConnectorMsgHdr tcpc_hdr(msg.get_length());

    if ( send( sock_fd, (const char*)&tcpc_hdr, sizeof(tcpc_hdr), 0 ) != sizeof(tcpc_hdr) )
    {
        ErrorMessage("TcpConnector: failed to transmit header\n");
        return false;
    }

    if ( send( sock_fd, (const char*)msg.get_data(), msg.get_length(), 0 ) != msg.get_length() )
        return false;

    return true;
}

bool TcpConnector::transmit_message(const ConnectorMsg& msg, const ID&)
{ return internal_transmit_message(msg); }

bool TcpConnector::transmit_message(const ConnectorMsg&& msg, const ID&)
{ return internal_transmit_message(msg); }

ConnectorMsg TcpConnector::receive_message(bool)
{
    // If socket isn't open, return 'no message'
    if ( sock_fd < 0 )
        return ConnectorMsg();

    ConnectorMsg* received_msg = receive_ring->get(nullptr);

    if ( !received_msg )
        return ConnectorMsg();

    ConnectorMsg ret_msg(std::move(*received_msg));
    delete received_msg;

    return ret_msg;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new TcpConnectorModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static TcpConnector* tcp_connector_tinit_call(const TcpConnectorConfig& cfg, const char* port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd = -1, s;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    if ( (s = getaddrinfo(cfg.address.c_str(), port, &hints, &result)) != 0)
    {
        ErrorMessage("getaddrinfo: %s\n", gai_strerror(s));
        return nullptr;
    }

   /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully connect.
       If socket(or connect fails, we (close the socket
       and) try the next address. */

    for (rp = result; rp != nullptr; rp = rp->ai_next)
    {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                  /* Success */

        close(sfd);
    }

    freeaddrinfo(result);           /* No longer needed */

    if (rp == nullptr)
    {               /* No address succeeded */
        ErrorMessage("Could not connect\n");
        return nullptr;
    }

    TcpConnector* tcp_conn = new TcpConnector(cfg, sfd);
    return tcp_conn;
}

static TcpConnector* tcp_connector_tinit_answer(const TcpConnectorConfig& cfg, const char* port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd = -1, s, peer_sfd;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = nullptr;
    hints.ai_addr = nullptr;
    hints.ai_next = nullptr;

    if ( (s = getaddrinfo(nullptr, port, &hints, &result)) != 0 )
    {
        ErrorMessage("getaddrinfo: %s\n", gai_strerror(s));
        return nullptr;
    }

   /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully bind).
       If socket) (or bind)) fails, we (close the socket
       and) try the next address. */

    for (rp = result; rp != nullptr; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype,
                rp->ai_protocol);
        if (sfd == -1)
            continue;

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;                  /* Success */

       close(sfd);
    }

    freeaddrinfo(result);           /* No longer needed */

    if (rp == nullptr)
    {
        ErrorMessage("Could not bind\n");
        return nullptr;
    }

    if ( listen(sfd, 10) < 0 )
    {
        char error_msg[1024] = { '\0' };
        if (strerror_r(errno, error_msg, sizeof(error_msg)) == 0)
            ErrorMessage("listen() failure: %s\n", error_msg);
        else
            ErrorMessage("listen() failure: %d\n", errno);
        return nullptr;
    }

    if ( (peer_sfd = accept(sfd, nullptr, nullptr )) < 0 )
    {
        char error_msg[1024] = { '\0' };
        if (strerror_r(errno, error_msg, sizeof(error_msg)) == 0)
            ErrorMessage("accept() failure: %s\n", error_msg);
        else
            ErrorMessage("accept() failure: %d\n", errno);
        return nullptr;
    }

    TcpConnector* tcp_conn = new TcpConnector(cfg, peer_sfd);
    return tcp_conn;
}

// Create a per-thread object
static Connector* tcp_connector_tinit(const ConnectorConfig& config)
{
    const TcpConnectorConfig& cfg = static_cast<const TcpConnectorConfig&>(config);
    const auto& ports = cfg.ports;
    auto idx = 0;

    if ( ports.size() > 1 )
        idx = get_instance_id() % ports.size();

    const char* port = ports[idx].c_str();

    TcpConnector* tcp_conn;

    if ( cfg.setup == TcpConnectorConfig::Setup::CALL )
        tcp_conn = tcp_connector_tinit_call(cfg, port);
    else if ( cfg.setup == TcpConnectorConfig::Setup::ANSWER )
        tcp_conn = tcp_connector_tinit_answer(cfg, port);
    else
        tcp_conn = nullptr;

    return tcp_conn;
}

static void tcp_connector_tterm(Connector* connector)
{
    TcpConnector* tcp_conn = (TcpConnector*)connector;

    delete tcp_conn;
}

static ConnectorCommon* tcp_connector_ctor(Module* m)
{
    TcpConnectorModule* mod = (TcpConnectorModule*)m;
    ConnectorCommon* tcp_connector_common = new ConnectorCommon(mod->get_and_clear_config());

    return tcp_connector_common;
}

static void tcp_connector_dtor(ConnectorCommon* c)
{
    delete c;
}

const ConnectorApi tcp_connector_api =
{
    {
        PT_CONNECTOR,
        sizeof(ConnectorApi),
        CONNECTOR_API_VERSION,
        2,
        API_RESERVED,
        API_OPTIONS,
        TCP_CONNECTOR_NAME,
        TCP_CONNECTOR_HELP,
        mod_ctor,
        mod_dtor
    },
    0,
    nullptr,
    nullptr,
    tcp_connector_tinit,
    tcp_connector_tterm,
    tcp_connector_ctor,
    tcp_connector_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* tcp_connector[] =
#endif
{
    &tcp_connector_api.base,
    nullptr
};

