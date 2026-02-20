//--------------------------------------------------------------------------
// Copyright (C) 2015-2026 Cisco and/or its affiliates. All rights reserved.
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
#include "pub_sub/ssl_events.h"
#include "ssl_flow_data.h"

class SslMetadataEvent : public SslTlsMetadataBaseEvent
{
public:
    SslMetadataEvent(const TLSConnectionData& conn_data)
        : tls_connection_data(conn_data)
    { }

    virtual ~SslMetadataEvent() override
    { }

    int32_t get_version() const override;
    int32_t get_curve() const override;
    int32_t get_cipher() const override;
    const std::string& get_server_name_identifier() const override;
    const std::string& get_subject() const override;
    const std::string& get_issuer() const override;
    const std::string& get_validation_status() const override;
    const std::string& get_module_identifier() const override;

private:
    TLSConnectionData tls_connection_data;
    std::string validation_status;
};

class SslFlowData : public SslBaseFlowData
{
public:
    SslFlowData(const snort::Flow* flow, snort::Inspector*, const SSLData* = nullptr);
    ~SslFlowData() override;

    static void init()
    { assign_ssl_inspector_id(snort::FlowData::create_flow_data_id()); }

    SSLData& get_session() override
    { return session; }

    TLSConnectionData& get_tls_connection_data()
    { return tls_connection_data; }

public:
    struct {
        bool orig_flag : 1;
        bool switch_in : 1;
    } finalize_info;

private:
    SSLData session;
    TLSConnectionData tls_connection_data;
    const snort::Flow* flow_handle;
};

#endif
