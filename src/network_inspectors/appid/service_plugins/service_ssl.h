//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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

#include "service_detector.h"

class ServiceDiscovery;

class SslServiceDetector : public ServiceDetector
{
public:
    SslServiceDetector(ServiceDiscovery*);

    int validate(AppIdDiscoveryArgs&) override;
};

AppId getSslServiceAppId(short srcPort);
bool is_service_over_ssl(AppId);
void service_ssl_clean();
int ssl_detector_process_patterns();
int ssl_scan_hostname(const uint8_t*, size_t, AppId*, AppId*);
int ssl_scan_cname(const uint8_t*, size_t, AppId*, AppId*);
int ssl_add_cert_pattern(uint8_t*, size_t, uint8_t, AppId);
int ssl_add_cname_pattern(uint8_t*, size_t, uint8_t, AppId);
void ssl_detector_free_patterns();
bool setSSLSquelch(snort::Packet*, int type, AppId, AppIdInspector& inspector);

#endif

