//--------------------------------------------------------------------------
// Copyright (C) 2014-2025 Cisco and/or its affiliates. All rights reserved.
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
// mp_transport_manager.cc author Oleksandr Stepanov <ostepano@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "mp_transport_manager.h"

#include <unordered_map>

using namespace snort;

struct MPTransportHandler
{
    MPTransportHandler(MPTransport* transport, const MPTransportApi* api)
        : transport(transport), api(api) {}
    MPTransport* transport;
    const MPTransportApi* api;
};

static std::unordered_map<std::string, MPTransportHandler*> transports_map;

void MPTransportManager::instantiate(const MPTransportApi *api, Module *mod, SnortConfig*)
{
    if(transports_map.find(api->base.name) != transports_map.end())
    {
        return;
    }

    transports_map.insert(std::make_pair(api->base.name, new MPTransportHandler(api->ctor(mod), api)));
}

MPTransport *MPTransportManager::get_transport(const std::string &name)
{
    auto it = transports_map.find(name);
    if (it != transports_map.end())
    {
        return it->second->transport;
    }
    return nullptr;
}

void MPTransportManager::add_plugin(const MPTransportApi *api)
{
    if (api->pinit)
    {
        api->pinit();
    }
}

void MPTransportManager::thread_init()
{
    for (auto &transport : transports_map)
    {
        if (transport.second->api->tinit)
        {
            transport.second->api->tinit(transport.second->transport);
        }
    }
}

void MPTransportManager::thread_term()
{
    for (auto &transport : transports_map)
    {
        if (transport.second->api->tterm)
        {
            transport.second->api->tterm(transport.second->transport);
        }
    }
}

void MPTransportManager::term()
{
    for (auto &transport : transports_map)
    {
        if (transport.second->api->dtor)
        {
            transport.second->api->dtor(transport.second->transport);
        }
        if (transport.second->api->pterm)
        {
            transport.second->api->pterm();
        }
        delete transport.second;
    }
    transports_map.clear();
}
