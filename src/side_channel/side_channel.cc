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

// side_channel.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "side_channel.h"

#include <sys/time.h>

#include <cassert>

#include "framework/counts.h"
#include "managers/connector_manager.h"
#include "profiler/profiler_defs.h"

using namespace snort;

/* Globals ****************************************************************/

THREAD_LOCAL SimpleStats sc_stats;
THREAD_LOCAL ProfileStats sc_perf_stats;

struct SideChannelMapping
{
    SideChannel* sc;
    std::vector<std::string> connectors;
    PortBitSet ports;
};

typedef std::vector<SideChannelMapping*> SCMaps;

/* s_maps - built during configuration
   tls_maps - instantiated for each thread to
              hold the thread specific SideChannel's */
static SCMaps s_maps;
static THREAD_LOCAL SCMaps* tls_maps;

SideChannel* SideChannelManager::get_side_channel(SCPort port)
{
    if ( tls_maps )
        for ( auto& scm : * tls_maps )
        {
            if ( ( port <= scm->ports.size() ) && ( scm->ports.test(port) ) )
            {
                return scm->sc;
            }
        }

    return nullptr;
}

SideChannel::SideChannel()
{
    sequence = 0;
    default_port = 0;
    connector_receive = nullptr;
    connector_transmit = nullptr;
    receive_handler = nullptr;
}

void SideChannel::set_message_port(SCMessage* msg, SCPort port)
{
    assert ( msg );
    assert ( msg->hdr );
    msg->hdr->port = port;
}

void SideChannel::set_default_port(SCPort port)
{
    default_port = port;
}

void SideChannelManager::instantiate(const SCConnectors* connectors, const PortBitSet* ports)
{
    SideChannelMapping* scm = new SideChannelMapping;

    scm->sc = nullptr;
    scm->connectors = *connectors;
    scm->ports = *ports;

    s_maps.push_back(scm);
}

// Initialize state to be ready to accept configuration
void SideChannelManager::pre_config_init()
{
    s_maps.clear();
}

// Within each thread, instantiate the connectors, etc.
void SideChannelManager::thread_init()
{

    // First startup the connectors
    ConnectorManager::thread_init();

    /* New SideChannel map vector just for this thread */
    SCMaps* map_list = new SCMaps;

    /* Loop through all of the configured SideChannel's */
    for ( auto& scm : s_maps )
    {
        /* New SideChannel just for this thread */
        SideChannelMapping* map = new SideChannelMapping;
        SideChannel* sc = new SideChannel;
        map->sc = sc;
        map->ports = scm->ports;

        for ( auto& conn_name : scm->connectors )
        {
            Connector* connector = ConnectorManager::get_connector(conn_name);
            if ( connector == nullptr )
                continue;

            if ( connector->get_connector_direction() == Connector::CONN_DUPLEX )
            {
                sc->connector_receive = connector;
                sc->connector_transmit = connector;
            }

            if ( connector->get_connector_direction() == Connector::CONN_RECEIVE )
            {
                sc->connector_receive = connector;
            }

            if ( connector->get_connector_direction() == Connector::CONN_TRANSMIT )
            {
                sc->connector_transmit = connector;
            }
        }

        /* Save the thread specific map */
        map_list->push_back(map);
    }

    /* Finally, save the thread-specific list */
    tls_maps = map_list;
}

// Within each thread, shutdown the sidechannel
void SideChannelManager::thread_term()
{

    // First shutdown the connectors
    ConnectorManager::thread_term();

    if (tls_maps)
    {
        for ( auto& map : *tls_maps )
        {
            delete map->sc;
            delete map;
        }

        delete tls_maps;
    }
}

void SideChannelManager::term()
{
    for ( auto& scm : s_maps )
        delete scm;

    s_maps.clear();
}

// receive at most max_messages.  Zero indicates unlimited.
// return true iff we received any messages.
bool SideChannel::process(int max_messages)
{
    bool received_message = false;

    while (true)
    {
        // get message if one is available.
        ConnectorMsgHandle* handle = connector_receive->receive_message(false);

        // if none, we are complete
        if ( !handle )
            break;

        else if ( receive_handler )
        {
            SCMessage* msg = new SCMessage;

            // get the ConnectorMsg from the (at this point) abstract class
            ConnectorMsg* connector_msg = connector_receive->get_connector_msg(handle);

            msg->content = connector_msg->data;
            msg->content_length = connector_msg->length;

            // if the message is longer than the header, assume we have a header
            if ( connector_msg->length >= sizeof(SCMsgHdr) )
            {
                msg->sc = this;
                msg->connector = connector_receive;
                msg->hdr = (SCMsgHdr*)connector_msg->data;
                msg->content += sizeof(SCMsgHdr);
                msg->content_length -= sizeof( SCMsgHdr );
            }

            msg->handle = handle;   // link back to the underlying SCC message
            received_message = true;

            receive_handler(msg);
        }

        if ( (max_messages > 0) && (--max_messages == 0) )
            break;
    }
    return received_message;
}

void SideChannel::register_receive_handler(const SCProcessMsgFunc& handler)
{
    receive_handler = handler;
}

void SideChannel::unregister_receive_handler()
{
    receive_handler = nullptr;
}

SCMessage* SideChannel::alloc_transmit_message(uint32_t content_length)
{
    SCMessage* msg = new SCMessage;
    msg->handle = connector_transmit->alloc_message((content_length + sizeof(SCMsgHdr)),
        (const uint8_t**)&(msg->hdr));
    assert(msg->handle);

    msg->sc = this;
    msg->connector = connector_transmit;
    msg->content_length = content_length;
    msg->content = (uint8_t*)msg->hdr + sizeof(SCMsgHdr);
    msg->hdr->port = default_port;

    return msg;
}

bool SideChannel::discard_message(SCMessage* msg)
{
    assert(msg);
    assert(msg->handle);

    msg->connector->discard_message (msg->handle);
    delete msg;
    return true;
}

bool SideChannel::transmit_message(SCMessage* msg)
{
    bool return_value = false;

    if ( connector_transmit && msg->handle )
    {
        struct timeval tm;
        (void)gettimeofday(&tm,nullptr);
        msg->hdr->time_seconds = (uint64_t)tm.tv_sec;
        msg->hdr->time_u_seconds = (uint32_t)tm.tv_usec;
        msg->hdr->sequence = sequence++;

        return_value = connector_transmit->transmit_message(msg->handle);
        delete msg;
    }

    return return_value;
}

Connector::Direction SideChannel::get_direction()
{
    if ( connector_receive && connector_transmit )
        return Connector::CONN_DUPLEX;
    if ( connector_receive && !connector_transmit )
        return Connector::CONN_RECEIVE;
    if ( !connector_receive && connector_transmit )
        return Connector::CONN_TRANSMIT;
    return Connector::CONN_UNDEFINED;
}
