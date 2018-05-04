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
#include "main/thread.h"
#include "profiler/profiler_defs.h"

#include "tcp_connector_module.h"

using namespace snort;

/* Globals ****************************************************************/

THREAD_LOCAL SimpleStats tcp_connector_stats;
THREAD_LOCAL ProfileStats tcp_connector_perfstats;

TcpConnectorMsgHandle::TcpConnectorMsgHandle(const uint32_t length)
{
    connector_msg.length = length;
    connector_msg.data = new uint8_t[length];
}

TcpConnectorMsgHandle::~TcpConnectorMsgHandle()
{
    delete[] connector_msg.data;
}

TcpConnectorCommon::TcpConnectorCommon(TcpConnectorConfig::TcpConnectorConfigSet* conf)
{
    config_set = (ConnectorConfig::ConfigSet*)conf;
}

TcpConnectorCommon::~TcpConnectorCommon()
{
    for ( auto conf : *config_set )
        delete conf;

    config_set->clear();
    delete config_set;
}

enum ReadDataOutcome { SUCCESS = 0, TRUNCATED, ERROR, CLOSED, PARTIAL, AGAIN };

static ReadDataOutcome read_data(int sockfd, uint8_t *data, uint16_t length, ssize_t *read_offset)
{
    ssize_t bytes_read, offset;

    offset = *read_offset;
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
    *read_offset = offset + bytes_read;
    if ((offset + bytes_read) < length)
        return PARTIAL;

    return SUCCESS;
}

static ReadDataOutcome read_message_data(int sockfd, uint16_t length, uint8_t *data)
{
    ssize_t offset;
    ReadDataOutcome rval;

    if ( length > 0 )
    {
        offset = 0;
        do
        {
            rval = read_data(sockfd, data, length, &offset);
        } while (rval == PARTIAL || rval == AGAIN);

        if (rval != SUCCESS)
            return rval;
    }

    return SUCCESS;
}


static TcpConnectorMsgHandle* read_message(int sock_fd)
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

    TcpConnectorMsgHandle* handle = new TcpConnectorMsgHandle(hdr.connector_msg_length);

    if ((outcome = read_message_data(sock_fd, hdr.connector_msg_length, handle->connector_msg.data)) != SUCCESS)
    {
        if (outcome == CLOSED)
            LogMessage("TcpC Input Thread: Connection closed while reading message data");
        else
            ErrorMessage("TcpC Input Thread: Unable to receive local message data: %d\n", (int)outcome);
        delete handle;
        return nullptr;
    }

    return handle;
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
            ErrorMessage("TcpC Input Thread: Error polling on socket %d: %s (%d)\n", pfds[0].fd, strerror(errno), errno);
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
        TcpConnectorMsgHandle* handle;
        if ( (handle = read_message(sock_fd)) != nullptr )
            if ( !receive_ring->put(handle) )
                ErrorMessage("TcpC Input Thread: overrun\n");
    }
}

void TcpConnector::receive_processing_thread()
{
    while (run_thread)
    {
        process_receive();
    }
}

void TcpConnector::start_receive_thread()
{
    run_thread = true;
    receive_thread = new std::thread(&TcpConnector::receive_processing_thread, this);
}

void TcpConnector::stop_receive_thread()
{
    if ( receive_thread != nullptr )
    {
        run_thread = false;
        receive_thread->join();
        delete receive_thread;
    }
}

TcpConnector::TcpConnector(TcpConnectorConfig* tcp_connector_config, int sfd)
{
    receive_thread = nullptr;
    config = tcp_connector_config;
    receive_ring = new ReceiveRing(50);
    sock_fd = sfd;
    if ( tcp_connector_config->async_receive )
        start_receive_thread();
}

TcpConnector::~TcpConnector()
{
    stop_receive_thread();
    delete receive_ring;
    close(sock_fd);
}

ConnectorMsgHandle* TcpConnector::alloc_message(const uint32_t length, const uint8_t** data)
{
    TcpConnectorMsgHandle* msg = new TcpConnectorMsgHandle(length);

    *data = (uint8_t*)msg->connector_msg.data;

    return msg;
}

void TcpConnector::discard_message(ConnectorMsgHandle* msg)
{
    TcpConnectorMsgHandle* tmsg = (TcpConnectorMsgHandle*)msg;
    delete tmsg;
}

bool TcpConnector::transmit_message(ConnectorMsgHandle* msg)
{
    TcpConnectorMsgHandle* tmsg = (TcpConnectorMsgHandle*)msg;

    if ( sock_fd < 0 )
    {
        ErrorMessage("TcpConnector: transmitting to a closed socket\n");
        delete tmsg;
        return false;
    }

    TcpConnectorMsgHdr tcpc_hdr(tmsg->connector_msg.length);

    if ( send( sock_fd, (const char*)&tcpc_hdr, sizeof(tcpc_hdr), 0 ) != sizeof(tcpc_hdr) )
    {
        ErrorMessage("TcpConnector: failed to transmit header\n");
        delete tmsg;
        return false;
    }

    if ( send( sock_fd, (const char*)tmsg->connector_msg.data, tmsg->connector_msg.length, 0 ) !=
        tmsg->connector_msg.length )
    {
        delete tmsg;
        return false;
    }

    delete tmsg;

    return true;
}

ConnectorMsgHandle* TcpConnector::receive_message(bool)
{
    // If socket isn't open, return 'no message'
    if ( sock_fd < 0 )
        return nullptr;

    return receive_ring->get(nullptr);
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

static TcpConnector* tcp_connector_tinit_call(TcpConnectorConfig* cfg, const char* port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd = -1, s;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    if ( (s = getaddrinfo(cfg->address.c_str(), port, &hints, &result)) != 0)
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

    TcpConnector* tcp_connector = new TcpConnector(cfg, sfd);
    return tcp_connector;
}

static TcpConnector* tcp_connector_tinit_answer(TcpConnectorConfig* cfg, const char* port)
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
        ErrorMessage("listen() failure: %s\n", strerror(errno));
        return nullptr;
    }

    if ( (peer_sfd = accept(sfd, nullptr, nullptr )) < 0 )
    {
        ErrorMessage("accept() failure: %s\n", strerror(errno));
        return nullptr;
    }

    TcpConnector* tcp_connector  = new TcpConnector(cfg, peer_sfd);
    return tcp_connector;
}

// Create a per-thread object
static Connector* tcp_connector_tinit(ConnectorConfig* config)
{
    TcpConnectorConfig* cfg = (TcpConnectorConfig*)config;

    uint16_t instance = (uint16_t)get_instance_id();
    char port_string[6];  // size based on decimal representation of an uint16_t

    if ( ((uint32_t)cfg->base_port + (uint32_t)instance) > (uint32_t)UINT16_MAX )
    {
        ErrorMessage("tcp_connector with improper base_port: %d\n",cfg->base_port);
        return nullptr;
    }

    snprintf(port_string, sizeof(port_string), "%5hu", static_cast<uint16_t>(cfg->base_port + instance));

    TcpConnector* tcp_connector;

    if ( cfg->setup == TcpConnectorConfig::Setup::CALL )
        tcp_connector = tcp_connector_tinit_call(cfg, port_string);
    else if ( cfg->setup == TcpConnectorConfig::Setup::ANSWER )
        tcp_connector = tcp_connector_tinit_answer(cfg, port_string);
    else
        tcp_connector = nullptr;

    return tcp_connector;
}

static void tcp_connector_tterm(Connector* connector)
{
    TcpConnector* tcp_connector = (TcpConnector*)connector;

    delete tcp_connector;
}

static ConnectorCommon* tcp_connector_ctor(Module* m)
{
    TcpConnectorModule* mod = (TcpConnectorModule*)m;
    TcpConnectorCommon* tcp_connector_common = new TcpConnectorCommon(
        mod->get_and_clear_config());

    return tcp_connector_common;
}

static void tcp_connector_dtor(ConnectorCommon* c)
{
    TcpConnectorCommon* fc = (TcpConnectorCommon*)c;
    delete fc;
}

const ConnectorApi tcp_connector_api =
{
    {
        PT_CONNECTOR,
        sizeof(ConnectorApi),
        CONNECTOR_API_VERSION,
        0,
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

