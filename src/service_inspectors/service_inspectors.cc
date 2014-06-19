/*
** Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2013-2013 Sourcefire, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "service_inspectors.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "framework/inspector.h"
#include "http_inspect/http_inspect.h"

extern const BaseApi* sin_http_global;
extern const BaseApi* sin_http_server;

#ifdef STATIC_INSPECTORS
extern const BaseApi* sin_bo;
extern const BaseApi* sin_ftp_client;
extern const BaseApi* sin_ftp_server;
extern const BaseApi* sin_rpc_decode;
extern const BaseApi* sin_telnet;
extern const BaseApi* sin_nhttp;
#endif

const BaseApi* service_inspectors[] =
{
    sin_http_global,
    sin_http_server,

    ips_http_uri,
    ips_http_header,
    ips_http_client_body,
    ips_http_method,
    ips_http_cookie,
    ips_http_stat_code,
    ips_http_stat_msg,
    ips_http_raw_uri,
    ips_http_raw_header,
    ips_http_raw_cookie,

#ifdef STATIC_INSPECTORS
    sin_bo,
    sin_ftp_client,
    sin_ftp_server,
    sin_rpc_decode,
    sin_telnet,
    sin_nhttp,
#endif
    nullptr,
};

