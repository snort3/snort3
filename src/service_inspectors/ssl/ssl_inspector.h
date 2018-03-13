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

#ifndef SSL_INSPECTOR_H
#define SSL_INSPECTOR_H

// Implementation header with definitions, datatypes and flowdata class for SSL service inspector.

#include "flow/flow.h"

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

class SslFlowData : public snort::FlowData
{
public:
    SslFlowData();
    ~SslFlowData() override;

    static void init()
    { inspector_id = snort::FlowData::create_flow_data_id(); }

public:
    static unsigned inspector_id;
    SSLData session;
};
//Function: API to get the ssl flow data from the packet flow.
SSLData* get_ssl_session_data(snort::Flow* flow);

#endif
