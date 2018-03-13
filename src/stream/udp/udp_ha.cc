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
// udp_ha.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "udp_ha.h"

#include "stream/stream.h"

#include "udp_session.h"

using namespace snort;

Flow* UdpHA::create_session(FlowKey* key)
{
    assert(key);

    Flow* flow = Stream::new_flow(key);

    if ( (flow != nullptr ) && (flow->session == nullptr) )
    {
        flow->init(PktType::UDP);
        flow->session = new UdpSession(flow);
    }

    return flow;
}

THREAD_LOCAL UdpHA* UdpHAManager::udp_ha = nullptr;

void UdpHAManager::process_deletion(Flow* flow)
{
    if( udp_ha != nullptr )
        udp_ha->process_deletion(flow);
}

void UdpHAManager::tinit()
{
    if ( HighAvailabilityManager::active() )
        udp_ha = new UdpHA();
    else
        udp_ha = nullptr;
}

void UdpHAManager::tterm()
{
    if ( udp_ha != nullptr )
        delete udp_ha;
}

