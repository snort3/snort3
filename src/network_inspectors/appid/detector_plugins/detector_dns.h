//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

char* dns_parse_host(const uint8_t* host, uint8_t host_len);

struct DNSHeader;

class DnsValidator
{
protected:
    APPID_STATUS_CODE add_dns_query_info(AppIdSession&, uint16_t, const uint8_t*,
        uint8_t, uint16_t, uint16_t, AppidChangeBits&);
    APPID_STATUS_CODE add_dns_response_info(AppIdSession&, uint16_t, const uint8_t*,
        uint8_t, uint16_t, uint8_t, uint32_t, AppidChangeBits&);
    APPID_STATUS_CODE dns_validate_label(const uint8_t*, uint16_t&, uint16_t, uint8_t&, bool&);
    int dns_validate_query(const uint8_t*, uint16_t*, uint16_t, uint16_t, bool, AppIdSession&, AppidChangeBits&);
    int dns_validate_answer(const uint8_t*, uint16_t*, uint16_t,
        uint16_t, uint8_t, bool, AppIdSession&, AppidChangeBits&);
    int dns_validate_header(AppidSessionDirection, const DNSHeader*, bool, const AppIdSession&);
    int validate_packet(const uint8_t*, uint16_t, const int, bool, AppIdSession&, AppidChangeBits&);
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

