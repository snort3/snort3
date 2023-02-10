//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
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

#ifndef SSL_FLOW_DATA_H
#define SSL_FLOW_DATA_H

#include "flow/flow_data.h"

#define GID_SSL 137

#define     SSL_INVALID_CLIENT_HELLO               1
#define     SSL_INVALID_SERVER_HELLO               2
#define     SSL_ALERT_HB_REQUEST                   3
#define     SSL_ALERT_HB_RESPONSE                  4

struct SSLData
{
    uint32_t ssn_flags;
    uint16_t partial_rec_len[4];
};

namespace snort
{
    class Flow;
}

class SO_PUBLIC SslBaseFlowData : public snort::FlowData
{
public:
    SslBaseFlowData() : snort::FlowData(inspector_id) {}

    virtual SSLData& get_session() = 0;

public:
    static SSLData* get_ssl_session_data(snort::Flow* flow);
    static unsigned get_ssl_inspector_id() { return inspector_id; }

protected:
    static void assign_ssl_inspector_id(unsigned u) { inspector_id = u; }

private:
    static unsigned inspector_id;
};

#endif
