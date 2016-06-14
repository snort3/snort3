//--------------------------------------------------------------------------
// Copyright (C) 2014-2016 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

// service_ssl.h author Sourcefire Inc.

#ifndef SERVICE_SSL_H
#define SERVICE_SSL_H

#include "detector_plugins/detector_api.h"
#include "service_config.h"

extern struct RNAServiceValidationModule ssl_service_mod;
AppId getSslServiceAppId(short srcPort);
bool isSslServiceAppId(AppId appId);
void service_ssl_clean(ServiceSslConfig*);
int ssl_detector_process_patterns(ServiceSslConfig*);
int ssl_scan_hostname(const u_int8_t*, size_t, AppId*, AppId*, ServiceSslConfig*);
int ssl_scan_cname(const u_int8_t*, size_t, AppId*, AppId*, ServiceSslConfig*);
int ssl_add_cert_pattern(uint8_t*, size_t, uint8_t, AppId, ServiceSslConfig*);
int ssl_add_cname_pattern(uint8_t*, size_t, uint8_t, AppId, ServiceSslConfig*);
void ssl_detector_free_patterns(ServiceSslConfig*);
int setSSLSquelch(Packet* p, int type, AppId appId);

#endif

