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

// host_port_app_cache.h author Sourcefire Inc.

#ifndef HOST_PORT_APP_CACHE_H
#define HOST_PORT_APP_CACHE_H

#include "sfip/sfip_t.h"
#include "appid_api.h"

class AppIdConfig;
enum class IpProtocol : uint8_t;

struct HostPortKey
{
    sfip_t ip;
    uint16_t port;
    IpProtocol proto;
};

struct HostPortVal
{
    AppId appId;
    unsigned type;
};

void hostPortAppCacheInit(AppIdConfig*);
void hostPortAppCacheFini(AppIdConfig*);
// FIXIT-M: Should proto be IpProtocol or ProtocolId?
HostPortVal* hostPortAppCacheFind(
    const sfip_t*, uint16_t port, IpProtocol proto, const AppIdConfig*);

int hostPortAppCacheAdd(
    const in6_addr*, uint16_t port, IpProtocol proto, unsigned type, AppId, AppIdConfig*);
void hostPortAppCacheDump(const AppIdConfig*);

#endif

