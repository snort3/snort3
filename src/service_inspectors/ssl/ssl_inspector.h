//--------------------------------------------------------------------------
// Copyright (C) 2015-2024 Cisco and/or its affiliates. All rights reserved.
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
#include "ssl_flow_data.h"

class SslFlowData : public SslBaseFlowData
{
public:
    SslFlowData();
    ~SslFlowData() override;

    static void init()
    { assign_ssl_inspector_id(snort::FlowData::create_flow_data_id()); }

    SSLData& get_session() override
    { return session; }

public:
    struct {
        bool orig_flag : 1;
        bool switch_in : 1;
    } finalize_info;

private:
    SSLData session;
};

#endif
