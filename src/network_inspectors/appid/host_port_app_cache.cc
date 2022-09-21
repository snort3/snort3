//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
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

#include <map>

#include "host_port_app_cache.h"
#include "log/messages.h"
#include "main/thread.h"
#include "managers/inspector_manager.h"
#include "appid_config.h"
#include "appid_inspector.h"

using namespace snort;

HostPortVal* HostPortCache::find(const SfIp* ip, uint16_t port, IpProtocol protocol,
    const OdpContext& odp_ctxt)
{
    HostPortKey hk;

    hk.ip = *ip;
    hk.port = (odp_ctxt.allow_port_wildcard_host_cache)? 0 : port;
    hk.proto = protocol;

    std::map<HostPortKey, HostPortVal>::iterator it;
    it = cache.find(hk);
    if (it != cache.end())
        return &it->second;
    else
        return nullptr;
}

bool HostPortCache::add(const SnortConfig* sc, const SfIp* ip, uint16_t port, IpProtocol proto,
    unsigned type, AppId appId)
{
    HostPortKey hk;
    HostPortVal hv;

    hk.ip = *ip;
    AppIdInspector* inspector =
        (AppIdInspector*)InspectorManager::get_inspector(MOD_NAME, false, sc);
    assert(inspector);
    const AppIdContext& ctxt = inspector->get_ctxt();
    hk.port = (ctxt.get_odp_ctxt().allow_port_wildcard_host_cache)? 0 : port;
    hk.proto = proto;

    hv.appId = appId;
    hv.type = type;

    cache[ hk ] = hv;

    return true;
}


HostAppIdsVal* HostPortCache::find_on_first_pkt(const SfIp* ip, uint16_t port, IpProtocol protocol,
    const OdpContext& odp_ctxt)
{
    HostPortKey hk;

    hk.ip = *ip;
    hk.port = (odp_ctxt.allow_port_wildcard_host_cache)? 0 : port;
    hk.proto = protocol;

    std::map<HostPortKey, HostAppIdsVal>::iterator it;
    it = cache_first.find(hk);
    if (it != cache_first.end())
        return &it->second;
    else
        return nullptr;
}

bool HostPortCache::add_host(const SnortConfig* sc, const SfIp* ip, uint16_t port, IpProtocol proto,
    AppId protocol_appId, AppId client_appId, AppId web_appId, unsigned reinspect)
{
    HostPortKey hk;
    HostAppIdsVal hv;

    hk.ip = *ip;
    AppIdInspector* inspector =
        (AppIdInspector*)InspectorManager::get_inspector(MOD_NAME, false, sc);
    assert(inspector);
    const AppIdContext& ctxt = inspector->get_ctxt();
    hk.port = (ctxt.get_odp_ctxt().allow_port_wildcard_host_cache)? 0 : port;
    hk.proto = proto;

    hv.protocol_appId = protocol_appId;
    hv.client_appId = client_appId;
    hv.web_appId = web_appId;
    hv.reinspect = reinspect;

    cache_first[ hk ] = hv;

    return true;
}

void HostPortCache::dump()
{
    for ( auto& kv : cache )
    {
        char inet_buffer[INET6_ADDRSTRLEN];

        HostPortKey hk = kv.first;
        HostPortVal hv = kv.second;

        inet_ntop(AF_INET6, &hk.ip, inet_buffer, sizeof(inet_buffer));
        LogMessage("\tip=%s, \tport %d, \tip_proto %u, \ttype=%u, \tappId=%d\n",
            inet_buffer, hk.port, (unsigned)hk.proto, hv.type, hv.appId);
    }
}

