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

// host_port_app_cache.cc author Sourcefire Inc.

#include "host_port_app_cache.h"

#include "appid_config.h"
#include "hash/sfxhash.h"
#include "log/messages.h"
#include "sfip/sf_ip.h"

THREAD_LOCAL SFXHASH* hostPortCache = nullptr;

void hostPortAppCacheInit()
{
    auto hash = sfxhash_new( 2048, sizeof(HostPortKey), sizeof(HostPortVal),
            0, 0, nullptr, nullptr, 0);

    if ( hash )
        hostPortCache = hash;
    else
        ErrorMessage("failed to allocate HostPort map");
}

void hostPortAppCacheFini()
{
    if ( hostPortCache )
    {
        sfxhash_delete(hostPortCache);
        hostPortCache = nullptr;
    }
}

HostPortVal* hostPortAppCacheFind(const sfip_t* snort_ip, uint16_t port, IpProtocol protocol)
{
    HostPortKey hk;
    sfip_set_ip(&hk.ip, snort_ip);
    hk.port = port;
    hk.proto = protocol;

    return (HostPortVal*)sfxhash_find(hostPortCache, &hk);
}

int hostPortAppCacheAdd(const sfip_t* ip, uint16_t port, IpProtocol proto, unsigned type, AppId appId)
{
    HostPortKey hk;
    HostPortVal hv;
    memcpy(&hk.ip, ip, sizeof(hk.ip));
    hk.port = port;
    hk.proto = proto;
    hv.appId = appId;
    hv.type = type;

    return sfxhash_add(hostPortCache, &hk, &hv) ? 0 : 1;
}

void hostPortAppCacheDump()
{
    for ( SFXHASH_NODE* node = sfxhash_findfirst(hostPortCache);
        node;
        node = sfxhash_findnext(hostPortCache))
    {
        char inet_buffer[INET6_ADDRSTRLEN];
        HostPortKey* hk;
        HostPortVal* hv;

        hk = (HostPortKey*)node->key;
        hv = (HostPortVal*)node->data;

        inet_ntop(AF_INET6, &hk->ip, inet_buffer, sizeof(inet_buffer));
        printf("\tip=%s, \tport %d, \tip_proto %d, \ttype=%u, \tappId=%d\n", inet_buffer, hk->port,
            to_utype(hk->proto), hv->type, hv->appId);
    }
}

