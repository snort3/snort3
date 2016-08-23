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
// icmp_ha.cc author Ed Borgoyn <eborgoyn@cisco.com>

#include "icmp_ha.h"

#include "flow/flow_control.h"
#include "main/snort_debug.h"
#include "stream/icmp/icmp_session.h"
#include "stream/stream.h"

void IcmpHA::delete_session(Flow*)
{
    DebugMessage(DEBUG_HA,"IcmpHA::delete_session)\n");
}

Flow* IcmpHA::create_session(FlowKey* key)
{
    DebugMessage(DEBUG_HA,"IcmpHA::create_session\n");

    assert ( key );

    Flow* flow = flow_con->new_flow(key);

    if ( (flow != nullptr ) && (flow->session == nullptr) )
    {
        flow->init(PktType::ICMP);
        flow->session = new IcmpSession(flow);
    }

    return flow;

}

THREAD_LOCAL IcmpHA* IcmpHAManager::icmp_ha = nullptr;

void IcmpHAManager::process_deletion(Flow* flow)
{
    if( icmp_ha != nullptr )
        icmp_ha->process_deletion(flow);
}

void IcmpHAManager::tinit()
{
    if ( HighAvailabilityManager::active() )
        icmp_ha = new IcmpHA();
    else
        icmp_ha = nullptr;
}

void IcmpHAManager::tterm()
{
    if ( icmp_ha != nullptr )
        delete icmp_ha;
}

