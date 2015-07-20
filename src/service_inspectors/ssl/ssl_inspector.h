//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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

#ifndef SSL_INSPECTOR_H
#define SSL_INSPECTOR_H

// Implementation header with definitions, datatypes and flowdata class for SSL service inspector.

#include "protocols/packet.h"
#include "stream/stream_api.h"
#include "time/profiler.h"
#include "ssl_config.h"

#define SSLPP_ENCRYPTED_FLAGS \
    (SSL_HS_SDONE_FLAG | SSL_CLIENT_KEYX_FLAG | \
    SSL_CAPP_FLAG | SSL_SAPP_FLAG)
#define SSLPP_ENCRYPTED_FLAGS2 \
    (SSL_HS_SDONE_FLAG | SSL_CHANGE_CIPHER_FLAG | \
    SSL_CAPP_FLAG | SSL_SAPP_FLAG)

struct SSLData
{
    uint32_t ssn_flags;
    uint16_t partial_rec_len[4];
};

struct SSL_counters_t
{
    uint64_t stopped;
    uint64_t disabled;
    uint64_t decoded;
    uint64_t alerts;
    uint64_t cipher_change;
    uint64_t unrecognized;
    uint64_t completed_hs;
    uint64_t bad_handshakes;
    uint64_t hs_chello;
    uint64_t hs_shello;
    uint64_t hs_cert;
    uint64_t hs_skey;
    uint64_t hs_ckey;
    uint64_t hs_finished;
    uint64_t hs_sdone;
    uint64_t capp;
    uint64_t sapp;
};

class SslFlowData : public FlowData
{
public:
    SslFlowData() : FlowData(flow_id)
    { memset(&session, 0, sizeof(session)); }

    ~SslFlowData() { }

    static void init()
    { flow_id = FlowData::get_flow_id(); }

public:
    static unsigned flow_id;
    SSLData session;
};
//Function: API to get the ssl flow data from the packet flow.
SSLData* get_ssl_session_data(Flow* flow);

void SSL_InitGlobals(void);

#endif
