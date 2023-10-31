//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
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

// host_port_app_cache.h author Sourcefire Inc.

#ifndef HOST_PORT_APP_CACHE_H
#define HOST_PORT_APP_CACHE_H

#include <cstring>

#include "application_ids.h"
#include "protocols/protocol_ids.h"
#include "sfip/sf_ip.h"
#include "utils/cpp_macros.h"

namespace snort
{
    struct SnortConfig;
}

class OdpContext;

PADDING_GUARD_BEGIN
struct HostPortKey
{
    HostPortKey()
    {
        ip.clear();
        port = 0;
        proto = IpProtocol::PROTO_NOT_SET;
        padding = 0;
    }

    bool operator<(const HostPortKey& right) const
    {
        return memcmp((const uint8_t*) this, (const uint8_t*) &right, sizeof(*this)) < 0;
    }

    snort::SfIp ip;
    uint16_t port;
    IpProtocol proto;
    char padding;
};
PADDING_GUARD_END

PADDING_GUARD_BEGIN
struct FirstPktkey
{
    FirstPktkey()
    {
        max_network_range.clear();
        network_address.clear();
    }

    bool operator<(const FirstPktkey& right) const
    {
        if ((htonl(right.netmask[0]) < htonl(this->netmask[0])) or
            (htonl(right.netmask[1]) < htonl(this->netmask[1])) or
            (htonl(right.netmask[2]) < htonl(this->netmask[2])) or
            (htonl(right.netmask[3]) < htonl(this->netmask[3])))
            return true;
        else
            return false;
    }

    uint32_t netmask[4] = {};
    snort::SfIp max_network_range;
    snort::SfIp network_address;
    uint16_t port = 0;
    IpProtocol proto = IpProtocol::PROTO_NOT_SET;
    char padding = 0;
};
PADDING_GUARD_END

struct HostPortVal
{
    AppId appId;
    unsigned type;
};

struct HostAppIdsVal
{
    AppId protocol_appId;
    AppId client_appId;
    AppId web_appId;
    unsigned reinspect;
};

class HostPortCache
{
public:
    HostPortVal* find(const snort::SfIp*, uint16_t port, IpProtocol, const OdpContext&);
    bool add(const snort::SnortConfig*, const snort::SfIp*, uint16_t port, IpProtocol,
        unsigned type, AppId);

    HostAppIdsVal* find_on_first_pkt(const snort::SfIp*, uint16_t port, IpProtocol, const OdpContext&);
    bool add_host(const snort::SnortConfig*, const snort::SfIp*, uint32_t* netmask, uint16_t port, IpProtocol,
        AppId, AppId, AppId, unsigned reinspect);
    void dump();

    ~HostPortCache()
    {
        cache.clear();
        cache_first_ip.clear();
        cache_first_subnet.clear();
    }

private:

    std::map<HostPortKey, HostPortVal> cache;
    std::map<HostPortKey, HostAppIdsVal> cache_first_ip;
    std::multimap<FirstPktkey, HostAppIdsVal> cache_first_subnet;
};

#endif

