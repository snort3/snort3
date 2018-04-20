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
// tcp_ha.cc author Ed Borgoyn <eborgoyn@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_ha.h"

#include "stream/stream.h"

#include "tcp_session.h"

using namespace snort;

Flow* TcpHA::create_session(FlowKey* key)
{
    assert(key);

    Flow* flow = Stream::new_flow(key);

    if ( (flow != nullptr ) && (flow->session == nullptr) )
    {
        flow->init(PktType::TCP);
        flow->session = new TcpSession(flow);
    }

    return flow;

}

void TcpHA::deactivate_session(Flow* flow)
{
    assert( flow );
    if ( flow->session )
        ((TcpSession*)(flow->session))->clear_session(true, true, false);

    flow->session_state &= ~( STREAM_STATE_SYN | STREAM_STATE_SYN_ACK |
            STREAM_STATE_ACK | STREAM_STATE_ESTABLISHED );

    assert( flow->ha_state );
    flow->clear_session_flags( SSNFLAG_SEEN_CLIENT | SSNFLAG_SEEN_SERVER );
}

THREAD_LOCAL TcpHA* TcpHAManager::tcp_ha = nullptr;

void TcpHAManager::process_deletion(Flow* flow)
{
    if( tcp_ha != nullptr )
        tcp_ha->process_deletion(flow);
}

void TcpHAManager::tinit()
{
    if ( HighAvailabilityManager::active() )
        tcp_ha = new TcpHA();
    else
        tcp_ha = nullptr;
}

void TcpHAManager::tterm()
{
    if ( tcp_ha != nullptr )
        delete tcp_ha;
}

