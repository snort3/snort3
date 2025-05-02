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

// side_channel.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "side_channel.h"

#include <sys/time.h>

#include <algorithm>
#include <cassert>
#include <cstring>

#include "framework/counts.h"
#include "managers/connector_manager.h"
#include "profiler/profiler_defs.h"

#include "side_channel_format.h"

using namespace snort;

/* Globals ****************************************************************/

THREAD_LOCAL SimpleStats sc_stats;
THREAD_LOCAL ProfileStats sc_perf_stats;

struct SideChannelMapping
{
    SideChannel* sc;
    std::vector<std::string> connectors;
    PortBitSet ports;
    ScMsgFormat format;
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
    {
        auto it = std::find_if(tls_maps->begin(), tls_maps->end(),
            [port](const SideChannelMapping* scm)
            { return port <= scm->ports.size() && scm->ports.test(port); });
        if (it != tls_maps->end())
            return (*it)->sc;
    }
    return nullptr;
}

void SideChannel::set_default_port(SCPort port)
{
    default_port = port;
}

void SideChannelManager::instantiate(const SCConnectors* connectors, const PortBitSet* ports, ScMsgFormat fmt)
{
    SideChannelMapping* scm = new SideChannelMapping;

    scm->sc = nullptr;
    scm->connectors = *connectors;
    scm->ports = *ports;
    scm->format = fmt;

    s_maps.emplace_back(scm);
}

// Initialize state to be ready to accept configuration
void SideChannelManager::pre_config_init()
{
    s_maps.clear();
}

// Within each thread, instantiate the connectors, etc.
void SideChannelManager::thread_init()
{
    /* New SideChannel map vector just for this thread */
    SCMaps* map_list = new SCMaps;

    /* Loop through all of the configured SideChannel's */
    for ( auto& scm : s_maps )
    {
        /* New SideChannel just for this thread */
        SideChannelMapping* map = new SideChannelMapping;
        SideChannel* sc = new SideChannel(scm->format);
        map->sc = sc;
        map->ports = scm->ports;

        for ( const auto& conn_name : scm->connectors )
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
        map_list->emplace_back(map);
    }

    /* Finally, save the thread-specific list */
    tls_maps = map_list;
}

// Within each thread, shutdown the sidechannel
void SideChannelManager::thread_term()
{
    if (tls_maps)
    {
        for ( const auto& map : *tls_maps )
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
    s_maps.shrink_to_fit();
}

SideChannel::SideChannel(ScMsgFormat fmt) : msg_format(fmt)
{ }

// receive at most max_messages.  Zero indicates unlimited.
// return true iff we received any messages.
bool SideChannel::process(int max_messages)
{
    if(!connector_receive)
        return false;
    
    bool received_message = false;

    while (true)
    {
        // get message if one is available.
        ConnectorMsg connector_msg = connector_receive->receive_message(false);

        if ( connector_msg.get_length() > 0 and msg_format == ScMsgFormat::TEXT )
        {
            connector_msg = from_text((const char*)connector_msg.get_data(), connector_msg.get_length());
        }

        // if none or invalid, we are complete
        if ( connector_msg.get_length() == 0 )
            break;

        if ( receive_handler )
        {
            SCMessage* msg = new SCMessage(this, connector_receive, std::move(connector_msg));

            msg->content = const_cast<uint8_t*>(msg->cmsg.get_data());
            msg->content_length = msg->cmsg.get_length();

            // if the message is longer than the header, assume we have a header
            if ( msg->cmsg.get_length() > sizeof(SCMsgHdr) )
            {
                msg->content += sizeof(SCMsgHdr);
                msg->content_length -= sizeof( SCMsgHdr );
            }

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

SCMsgHdr SideChannel::get_header()
{
    struct timeval tm;
    (void)gettimeofday(&tm, nullptr);

    SCMsgHdr hdr;
    hdr.port = default_port;
    hdr.time_seconds = (uint64_t)tm.tv_sec;
    hdr.time_u_seconds = (uint32_t)tm.tv_usec;
    hdr.sequence = sequence++;

    return hdr;
}

SCMessage* SideChannel::alloc_transmit_message(uint32_t content_length)
{
    SCMessage* msg = nullptr;
    const SCMsgHdr sc_hdr = get_header();

    switch (msg_format)
    {
    case ScMsgFormat::BINARY:
    {
        uint8_t* msg_data = new uint8_t[sizeof(SCMsgHdr) + content_length];

        memcpy(msg_data, &sc_hdr, sizeof(SCMsgHdr));

        ConnectorMsg bin_cmsg(msg_data, sizeof(SCMsgHdr) + content_length, true);

        msg = new SCMessage(this, connector_transmit, std::move(bin_cmsg));
        msg->content = msg_data + sizeof(SCMsgHdr);
        msg->content_length = content_length;

        break;
    }

    case ScMsgFormat::TEXT:
    {
        std::string hdr_text = sc_msg_hdr_to_text(&sc_hdr);

        if (hdr_text.empty())
            break;

        const uint32_t msg_len = hdr_text.size() + (content_length * TXT_UNIT_LEN);
        uint8_t* msg_data = new uint8_t[msg_len];

        memcpy(msg_data, hdr_text.c_str(), hdr_text.size());

        ConnectorMsg text_cmsg(msg_data, msg_len, true);

        msg = new SCMessage(this, connector_transmit, std::move(text_cmsg));
        msg->content = msg_data + hdr_text.size();
        msg->content_length = content_length;

        break;
    }

    default:
        break;
    }

    return msg;
}

bool SideChannel::discard_message(SCMessage* msg) const
{
    assert(msg);

    delete msg;

    return true;
}

bool SideChannel::transmit_message(SCMessage* msg) const
{
    if(!msg)
        return false;

    if ( !connector_transmit)
    {
        delete msg;
        return false;
    }

    if ( msg_format == ScMsgFormat::TEXT )
    {
        std::string text = sc_msg_data_to_text(msg->content, msg->content_length);

        if ( text.size() != msg->cmsg.get_length() - (uint32_t)(msg->content - msg->cmsg.get_data()) )
        {
            delete msg;
            return false;
        }

        memcpy(msg->content, text.c_str(), text.size());
    }

    bool return_value = connector_transmit->transmit_message(msg->cmsg);

    delete msg;

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
