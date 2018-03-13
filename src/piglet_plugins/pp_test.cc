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
// pp_test.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "piglet/piglet_api.h"

#include "pp_buffer_iface.h"
#include "pp_codec_data_iface.h"
#include "pp_cursor_iface.h"
#include "pp_daq_pkthdr_iface.h"
#include "pp_decode_data_iface.h"
#include "pp_enc_state_iface.h"
#include "pp_event_iface.h"
#include "pp_flow_iface.h"
#include "pp_ip_api_iface.h"
#include "pp_packet_iface.h"
#include "pp_raw_buffer_iface.h"

using namespace snort;

class TestPiglet : public Piglet::BasePlugin
{
public:
    TestPiglet(Lua::State& state, const std::string& target) :
        BasePlugin(state, target) { }

    bool setup() override;
};

bool TestPiglet::setup()
{
    // FIXIT-L would like to be able to selectively load lua interfaces
    install(L, BufferIface);
    install(L, CodecDataIface);
    install(L, CursorIface);
    install(L, DAQHeaderIface);
    install(L, DecodeDataIface);
    install(L, EncStateIface);
    install(L, EventIface);
    install(L, FlowIface);
    install(L, IpApiIface);
    install(L, PacketIface);
    install(L, RawBufferIface);

    return false;
}

// -----------------------------------------------------------------------------
// API foo
// -----------------------------------------------------------------------------
static Piglet::BasePlugin* ctor(
    Lua::State& state, const std::string& target, Module*, SnortConfig*)
{ return new TestPiglet(state, target); }

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
        "pp_test",
        "Test piglet",
        nullptr,
        nullptr
    },
    ctor,
    dtor,
    PT_PIGLET
};

const BaseApi* pp_test = &piglet_api.base;
