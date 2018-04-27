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

// detector_dns.h author Sourcefire Inc.

#ifndef DETECTOR_DNS_H
#define DETECTOR_DNS_H

#include "service_plugins/service_detector.h"

int dns_host_scan_hostname(const uint8_t*, size_t, AppId*, AppId*);
void service_dns_host_clean();
int dns_host_detector_process_patterns();
int dns_add_host_pattern(uint8_t*, size_t, uint8_t, AppId);
void dns_detector_free_patterns();
char* dns_parse_host(const uint8_t* host, uint8_t host_len);

struct DNSHeader;

class DnsValidator
{
public:
    void add_dns_query_info(AppIdSession&, uint16_t id, const uint8_t* host, uint8_t host_len,
        uint16_t host_offset, uint16_t record_type);
    void add_dns_response_info(AppIdSession&, uint16_t id, const uint8_t* host,
        uint8_t host_len, uint16_t host_offset, uint8_t response_type, uint32_t ttl);
    int dns_validate_label(const uint8_t* data, uint16_t* offset, uint16_t size, uint8_t* len,
        unsigned* len_valid);
    int dns_validate_query(const uint8_t* data, uint16_t* offset, uint16_t size,
        uint16_t id, bool host_reporting, AppIdSession&);
    int dns_validate_answer(const uint8_t* data, uint16_t* offset, uint16_t size,
        uint16_t id, uint8_t rcode, bool host_reporting, AppIdSession&);
    int dns_validate_header(const AppidSessionDirection dir, const DNSHeader*, bool host_reporting, AppIdSession&);
    int validate_packet(const uint8_t* data, uint16_t size, const int,
        bool host_reporting, AppIdSession&);
};

class DnsTcpServiceDetector : public ServiceDetector, public DnsValidator
{
public:
    DnsTcpServiceDetector(ServiceDiscovery*);

    int validate(AppIdDiscoveryArgs&) override;
};

class DnsUdpServiceDetector : public ServiceDetector, public DnsValidator
{
public:
    DnsUdpServiceDetector(ServiceDiscovery*);

    int validate(AppIdDiscoveryArgs&) override;
};
#endif

