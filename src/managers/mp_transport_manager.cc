//--------------------------------------------------------------------------
// Copyright (C) 2014-2026 Cisco and/or its affiliates. All rights reserved.
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

#include "plugin_manager.h"
#include "plug_interface.h"

using namespace snort;

class MPTPlugInterface : public PlugInterface
{
public:
    MPTPlugInterface(const MPTransportApi* api) : api(api) { }

    void global_init() override
    {
        if (api->pinit)
            api->pinit();
    }

    void global_term() override
    {
        if (api->pterm)
            api->pterm();
    }

    void thread_init() override
    {
        if (api->tinit)
            api->tinit(transport);
    }

    void thread_term() override
    {
        if (api->tterm)
            api->tterm(transport);
    }

    void instantiate(Module* mod, SnortConfig*, const char*) override
    {
        transport = api->ctor(mod);
    }

public:
    MPTransport* transport = nullptr;
    const MPTransportApi* api;
};

PlugInterface* MPTransportManager::get_interface(const MPTransportApi * api)
{ return new MPTPlugInterface(api); }

MPTransport *MPTransportManager::get_transport(const std::string &name)
{
    if (auto* p = PluginManager::get_interface(name.c_str()))
    {
        MPTPlugInterface* mp = (MPTPlugInterface*)p;
        return mp->transport;
    }

    return nullptr;
}

void MPTransportManager::term()
{
    auto dtor = [](PlugInterface* pin, void*)
    {
        MPTPlugInterface* mp = (MPTPlugInterface*)pin;
        mp->api->dtor(mp->transport);
    };
    PluginManager::for_each(PT_MP_TRANSPORT, dtor);
}

