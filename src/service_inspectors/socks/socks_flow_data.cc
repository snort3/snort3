//--------------------------------------------------------------------------
// Copyright (C) 2026 Cisco and/or its affiliates. All rights reserved.
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
// socks_flow_data.cc - author Raza Shafiq <rshafiq@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "socks_flow_data.h"
#include "socks_module.h"

using namespace snort;

unsigned SocksFlowData::inspector_id = 0;

void SocksFlowData::init()
{
    if ( inspector_id == 0 )
        inspector_id = FlowData::create_flow_data_id();
}

SocksFlowData::SocksFlowData() : FlowData(inspector_id),
    state(SOCKS_STATE_INIT),
    direction(SOCKS_DIR_CLIENT_TO_SERVER),
    initiator(SOCKS_INITIATOR_UNKNOWN),
    socks_version(0),
    is_socks4a_protocol(false),
    auth_method(SOCKS5_AUTH_NONE),
    command(SOCKS_CMD_CONNECT),
    target(),
    bind(),
    request_count(0),
    response_count(0),
    last_error(SOCKS5_REP_SUCCESS),
    handoff_pending(false),
    handoff_completed(false),
    session_counted(false)
{
    ++socks_stats.concurrent_sessions;
    if (socks_stats.concurrent_sessions > socks_stats.max_concurrent_sessions)
        socks_stats.max_concurrent_sessions = socks_stats.concurrent_sessions;
}

SocksFlowData::~SocksFlowData() noexcept
{
    assert(socks_stats.concurrent_sessions > 0);
    --socks_stats.concurrent_sessions;
}
