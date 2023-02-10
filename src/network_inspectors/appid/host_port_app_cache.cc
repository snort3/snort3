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

inline void apply_min_ip_range(SfIp& ip, const uint32_t* netmask)
{
    if (ip.get_family() == AF_INET)
    {
        uint32_t tmp_val = ip.get_ip4_value() & netmask[3];
        ip.set(&tmp_val, AF_INET);
    }
    else if (ip.get_family() == AF_INET6)
    {
        uint32_t* tmp_val = const_cast<uint32_t*>(ip.get_ip6_ptr());
        tmp_val[0] = tmp_val[0] & netmask[0];
        tmp_val[1] = tmp_val[1] & netmask[1];
        tmp_val[2] = tmp_val[2] & netmask[2];
        tmp_val[3] = tmp_val[3] & netmask[3];
        ip.set(tmp_val, AF_INET6);
    }
}

inline void apply_max_ip_range(SfIp& ip, const uint32_t* netmask)
{
    if (ip.get_family() == AF_INET)
    {
        uint32_t tmp_val = ip.get_ip4_value() | ~netmask[3];
        ip.set(&tmp_val, AF_INET);
    }
    else if (ip.get_family() == AF_INET6)
    {
        uint32_t* tmp_val = const_cast<uint32_t*>(ip.get_ip6_ptr());

        tmp_val[0] = tmp_val[0] | ~netmask[0];
        tmp_val[1] = tmp_val[1] | ~netmask[1];
        tmp_val[2] = tmp_val[2] | ~netmask[2];
        tmp_val[3] = tmp_val[3] | ~netmask[3];

        ip.set(tmp_val, AF_INET6);
    }
}

inline bool check_ip_range(const SfIp& max, const SfIp& min, const SfIp& ip, const uint32_t* netmask)
{
    if (max.get_family() != ip.get_family())
        return false;

    if (max.is_ip4())
    {
        SfIp tmp = ip;
        apply_min_ip_range(tmp, netmask);
        if (tmp.get_ip4_value() == min.get_ip4_value())
        {
            apply_max_ip_range(tmp, netmask);
            return tmp.get_ip4_value() == max.get_ip4_value();
        }
    }
    else if (max.is_ip6())
    {
        SfIp tmp = ip;
        apply_min_ip_range(tmp, netmask);
        if (memcmp(tmp.get_ip6_ptr(), min.get_ip6_ptr(), 16) == 0)
        {
            apply_max_ip_range(tmp, netmask);
            return memcmp(tmp.get_ip6_ptr(), max.get_ip6_ptr(), 16) == 0;
        }
    }

    return false;
}

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
    uint16_t lookup_port = (odp_ctxt.allow_port_wildcard_host_cache)? 0 : port;

    if (!cache_first_ip.empty())
    {
        HostPortKey hk;

        hk.ip = *ip;
        hk.port = lookup_port;
        hk.proto = protocol;

        std::map<HostPortKey, HostAppIdsVal>::iterator check_cache;
        check_cache = cache_first_ip.find(hk);
        if (check_cache != cache_first_ip.end())
            return &check_cache->second;
    }

    for (std::map<FirstPktkey ,HostAppIdsVal>::iterator iter = cache_first_subnet.begin(); iter != cache_first_subnet.end(); ++iter)
    {
        if (iter->first.port == lookup_port and iter->first.proto == protocol and
            check_ip_range(iter->first.max_network_range, iter->first.network_address, *ip, &iter->first.netmask[0]))
        {
            return &iter->second;
        }
    }
    
    return nullptr;
}

bool HostPortCache::add_host(const SnortConfig* sc, const SfIp* ip, uint32_t* netmask, uint16_t port, IpProtocol proto,
    AppId protocol_appId, AppId client_appId, AppId web_appId, unsigned reinspect)
{
    if (!netmask)
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

        cache_first_ip[ hk ] = hv;
    }
    else 
    {
        FirstPktkey hk;
        HostAppIdsVal hv;

        hk.network_address = *ip;
        apply_min_ip_range(hk.network_address, netmask);
        hk.max_network_range = hk.network_address;
        apply_max_ip_range(hk.max_network_range, netmask);

        memcpy(&hk.netmask[0], netmask, 16);
        
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

        cache_first_subnet.emplace(hk, hv);
    }
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

