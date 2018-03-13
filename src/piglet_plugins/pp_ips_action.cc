//--------------------------------------------------------------------------
// Copyright (C) 2015-2018 Cisco and/or its affiliates. All rights reserved.
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
// pp_ips_action.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "managers/action_manager.h"
#include "piglet/piglet_api.h"

#include "pp_ips_action_iface.h"
#include "pp_packet_iface.h"
#include "pp_raw_buffer_iface.h"

using namespace snort;

class IpsActionPiglet : public Piglet::BasePlugin
{
public:
    IpsActionPiglet(Lua::State&, const std::string&, Module*, SnortConfig*);
    ~IpsActionPiglet() override;
    bool setup() override;

private:
    IpsActionWrapper* wrapper;
};

IpsActionPiglet::IpsActionPiglet(
    Lua::State& state, const std::string& target, Module* m, SnortConfig* sc) :
    BasePlugin(state, target, m, sc)
{
    if ( module )
        wrapper = ActionManager::instantiate(target.c_str(), m);
}

IpsActionPiglet::~IpsActionPiglet()
{
    if ( wrapper )
        delete wrapper;
}

bool IpsActionPiglet::setup()
{
    if ( !wrapper )
        return true;

    install(L, RawBufferIface);
    install(L, PacketIface);

    install(L, IpsActionIface, wrapper->instance);

    return false;
}

// -----------------------------------------------------------------------------
// API foo
// -----------------------------------------------------------------------------
static Piglet::BasePlugin* ctor(
    Lua::State& state, const std::string& target, Module* m, SnortConfig* sc)
{ return new IpsActionPiglet(state, target, m, sc); }

static void dtor(Piglet::BasePlugin* p)
{ delete p; }

static const struct Piglet::Api piglet_api =
{
    {
        PT_PIGLET,
        sizeof(Piglet::Api),
        PIGLET_API_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "pp_ips_action",
        "Ips action piglet",
        nullptr,
        nullptr
    },
    ctor,
    dtor,
    PT_IPS_ACTION
};

const BaseApi* pp_ips_action = &piglet_api.base;
