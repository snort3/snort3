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
// pp_inspector.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "managers/inspector_manager.h"
#include "piglet/piglet_api.h"
#include "stream/flush_bucket.h"

#include "pp_decode_data_iface.h"
#include "pp_flow_iface.h"
#include "pp_inspector_iface.h"
#include "pp_ip_api_iface.h"
#include "pp_packet_iface.h"
#include "pp_raw_buffer_iface.h"
#include "pp_stream_splitter_iface.h"

using namespace snort;

class InspectorPiglet : public Piglet::BasePlugin
{
public:
    InspectorPiglet(Lua::State&, const std::string&, Module*, SnortConfig*);
    bool setup() override;

private:
    Inspector* instance;
};

InspectorPiglet::InspectorPiglet(
    Lua::State& state, const std::string& target, Module* m, SnortConfig* sc) :
    BasePlugin(state, target, m, sc)
{
    FlushBucket::set(0);

    assert(module);
    assert(snort_conf);

    instance = InspectorManager::instantiate(target.c_str(), module, snort_conf);
}


bool InspectorPiglet::setup()
{
    if ( !instance )
    {
        Piglet::error("couldn't instantiate Inspector '%s'", target.c_str());
        return true;
    }

    install(L, DecodeDataIface);
    install(L, RawBufferIface);
    install(L, FlowIface);
    install(L, IpApiIface);
    install(L, PacketIface);
    install(L, StreamSplitterIface);

    install(L, InspectorIface, instance);

    return false;
}

// -----------------------------------------------------------------------------
// API foo
// -----------------------------------------------------------------------------
static Piglet::BasePlugin* ctor(
    Lua::State& state, const std::string& target, Module* m, SnortConfig* sc)
{ return new InspectorPiglet(state, target, m, sc); }

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
        "pp_inspector",
        "Inspector piglet",
        nullptr,
        nullptr
    },
    ctor,
    dtor,
    PT_INSPECTOR
};

const BaseApi* pp_inspector = &piglet_api.base;
