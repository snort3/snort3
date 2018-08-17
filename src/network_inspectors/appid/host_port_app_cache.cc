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

// host_port_app_cache.cc author Sourcefire Inc.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "host_port_app_cache.h"

#include <map>

#include "log/messages.h"
#include "main/thread.h"
#include "sfip/sf_ip.h"
#include "utils/cpp_macros.h"

using namespace snort;

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

    bool operator<(HostPortKey right) const
    {
        if ( ip.less_than(right.ip) )
            return true;
        else if ( right.ip.less_than(ip) )
            return false;
        else
        {
            if ( port < right.port)
                return true;
            else if ( right.port < port )
                return false;
            else if ( proto < right.proto)
                return true;
            else
                return false;
        }
    }

    SfIp ip;
    uint16_t port;
    IpProtocol proto;
    char padding;
};
PADDING_GUARD_END

static std::map<HostPortKey, HostPortVal>* host_port_cache = nullptr;

void HostPortCache::initialize()
{
    host_port_cache = new std::map<HostPortKey, HostPortVal>;
}

void HostPortCache::terminate()
{
    if (host_port_cache)
    {
        host_port_cache->clear();
        delete host_port_cache;
        host_port_cache = nullptr;
    }
}

HostPortVal* HostPortCache::find(const SfIp* ip, uint16_t port, IpProtocol protocol)
{
    HostPortKey hk;

    hk.ip.set(*ip);
    hk.port = port;
    hk.proto = protocol;

    std::map<HostPortKey, HostPortVal>::iterator it;
    it = host_port_cache->find(hk);
    if (it != host_port_cache->end())
        return &it->second;
    else
        return nullptr;
}

bool HostPortCache::add(const SfIp* ip, uint16_t port, IpProtocol proto, unsigned type, AppId
    appId)
{
    HostPortKey hk;
    HostPortVal hv;

    hk.ip.set(*ip);
    hk.port = port;
    hk.proto = proto;

    hv.appId = appId;
    hv.type = type;

    (*host_port_cache)[ hk ] = hv;

    return true;
}

void HostPortCache::dump()
{
    for ( auto& kv : *host_port_cache )
    {
        char inet_buffer[INET6_ADDRSTRLEN];

        HostPortKey hk = kv.first;
        HostPortVal hv = kv.second;

        inet_ntop(AF_INET6, &hk.ip, inet_buffer, sizeof(inet_buffer));
        LogMessage("\tip=%s, \tport %d, \tip_proto %u, \ttype=%u, \tappId=%d\n",
            inet_buffer, hk.port, (unsigned)hk.proto, hv.type, hv.appId);
    }
}

