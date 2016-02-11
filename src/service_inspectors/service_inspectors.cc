//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "service_inspectors.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "framework/inspector.h"

extern const BaseApi* sin_http_global;
extern const BaseApi* sin_http_inspect;
extern const BaseApi* sin_imap;
extern const BaseApi* sin_pop;
extern const BaseApi* sin_smtp;
extern const BaseApi* sin_ssl;
extern const BaseApi* ips_ssl_state;
extern const BaseApi* ips_ssl_version;

#ifdef STATIC_INSPECTORS
extern const BaseApi* ips_dce_iface;
extern const BaseApi* ips_dce_opnum;
extern const BaseApi* ips_dce_stub_data;
extern const BaseApi* ips_dnp3_data;
extern const BaseApi* ips_dnp3_func;
extern const BaseApi* ips_dnp3_ind;
extern const BaseApi* ips_dnp3_obj;
extern const BaseApi* ips_gtp_info;
extern const BaseApi* ips_gtp_type;
extern const BaseApi* ips_gtp_version;
extern const BaseApi* ips_modbus_data;
extern const BaseApi* ips_modbus_func;
extern const BaseApi* ips_modbus_unit;
extern const BaseApi* ips_sip_body;
extern const BaseApi* ips_sip_header;
extern const BaseApi* ips_sip_method;
extern const BaseApi* ips_sip_stat_code;

extern const BaseApi* sin_bo;
extern const BaseApi* sin_dce_smb;
extern const BaseApi* sin_dce_tcp;
extern const BaseApi* sin_dnp3;
extern const BaseApi* sin_dns;
extern const BaseApi* sin_ftp_client;
extern const BaseApi* sin_ftp_server;
extern const BaseApi* sin_ftp_data;
extern const BaseApi* sin_gtp;
extern const BaseApi* sin_modbus;
extern const BaseApi* sin_nhttp;
extern const BaseApi* sin_rpc_decode;
extern const BaseApi* sin_sip;
extern const BaseApi* sin_ssh;
extern const BaseApi* sin_telnet;
extern const BaseApi* sin_wizard;
#endif

const BaseApi* service_inspectors[] =
{
    sin_http_global,
    sin_http_inspect,
    sin_imap,
    sin_pop,
    sin_smtp,
    sin_ssl,
    ips_ssl_state,
    ips_ssl_version,

#ifdef STATIC_INSPECTORS
    ips_dce_iface,
    ips_dce_opnum,
    ips_dce_stub_data,
    ips_dnp3_data,
    ips_dnp3_func,
    ips_dnp3_ind,
    ips_dnp3_obj,
    ips_gtp_info,
    ips_gtp_type,
    ips_gtp_version,
    ips_modbus_data,
    ips_modbus_func,
    ips_modbus_unit,
    ips_sip_body,
    ips_sip_header,
    ips_sip_method,
    ips_sip_stat_code,

    sin_bo,
    sin_dce_smb,
    sin_dce_tcp,
    sin_dnp3,
    sin_dns,
    sin_ftp_client,
    sin_ftp_server,
    sin_ftp_data,
    sin_gtp,
    sin_modbus,
    sin_nhttp,
    sin_rpc_decode,
    sin_sip,
    sin_ssh,
    sin_telnet,
    sin_wizard,
#endif
    nullptr
};

