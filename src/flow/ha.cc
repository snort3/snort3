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
// ha.cc author Ed Borgoyn <eborgoyn@cisco.com>

#include "ha.h"

#include <assert.h>
#include <functional>

#include "flow.h"
#include "main/snort_debug.h"
#include "packet_io/sfdaq.h"
#include "side_channel/side_channel.h"

static THREAD_LOCAL HighAvailability* ha;

HighAvailability::HighAvailability()
{
    using namespace std::placeholders;
    DebugMessage(DEBUG_HA,"HighAvailability::HighAvailability()\n");

    sc = SideChannelManager::get_side_channel( (SCPort)1);

    // If we don't have a side channel, move-on and don't perform ha processing.
    if ( !sc )
        return;

    sc->set_default_port(1);
    sc->register_receive_handler(std::bind(&HighAvailability::receive_handler, this, _1));
}

HighAvailability::~HighAvailability()
{
    DebugMessage(DEBUG_HA,"HighAvailability::~HighAvailability()\n");

    // If we don't have a side channel, move-on and don't perform ha processing.
    if ( !sc )
        return;

    sc->unregister_receive_handler();
    delete sc;
}

void HighAvailability::receive_handler(SCMessage* msg)
{
    assert(msg);

    DebugFormat(DEBUG_HA,"HighAvailability::receive_handler: port: %d, length: %d\n",
        msg->hdr->port, msg->content_length);
    if ( msg->sc )
        msg->sc->discard_message(msg);
}

void HighAvailability::process(Flow*, const DAQ_PktHdr_t* pkthdr)
{
    DebugMessage(DEBUG_HA,"HighAvailability::process()\n");

    const uint32_t msg_len = 21; // up to 20 digits + trailing null

    if ( !sc )
        return;

    SCMessage* msg = sc->alloc_transmit_message(msg_len);
    snprintf((char*)msg->content, msg_len, "%20" PRIu64, (uint64_t)pkthdr->ts.tv_sec);
    sc->transmit_message(msg);

    sc->process(4);
}

void HighAvailabilityManager::thread_init()
{
    DebugMessage(DEBUG_HA,"HighAvailabilityManager::thread_init()\n");
    ha = new HighAvailability();
}

void HighAvailabilityManager::thread_term()
{
    DebugMessage(DEBUG_HA,"HighAvailabilityManager::thread_term()\n");
    delete ha;
}

void HighAvailabilityManager::process(Flow* flow, const DAQ_PktHdr_t* pkthdr)
{
    ha->process(flow,pkthdr);
}

