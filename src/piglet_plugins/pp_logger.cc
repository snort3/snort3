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
// pp_logger.cc author Joel Cornett <jocornet@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "managers/event_manager.h"
#include "piglet/piglet_api.h"

#include "pp_decode_data_iface.h"
#include "pp_event_iface.h"
#include "pp_ip_api_iface.h"
#include "pp_logger_iface.h"
#include "pp_packet_iface.h"
#include "pp_raw_buffer_iface.h"

using namespace snort;

class LoggerPiglet : public Piglet::BasePlugin
{
public:
    LoggerPiglet(Lua::State&, const std::string&, Module*, SnortConfig*);
    ~LoggerPiglet() override;
    bool setup() override;

private:
    LoggerWrapper* wrapper;
};

LoggerPiglet::LoggerPiglet(
    Lua::State& state, const std::string& target, Module* m, SnortConfig* sc) :
    BasePlugin(state, target, m, sc)
{
    // FIXIT-M does Logger need module?
    if ( module )
        wrapper = EventManager::instantiate(target.c_str(), m, sc);
}

LoggerPiglet::~LoggerPiglet()
{
    if ( wrapper )
        delete wrapper;
}

bool LoggerPiglet::setup()
{
    if ( !wrapper )
        return true;

    install(L, RawBufferIface);
    install(L, DecodeDataIface);
    install(L, IpApiIface);
    install(L, PacketIface);
    install(L, EventIface);

    install(L, LoggerIface, wrapper->instance);

    return false;
}

// -----------------------------------------------------------------------------
// API foo
// -----------------------------------------------------------------------------
static Piglet::BasePlugin* ctor(
    Lua::State& state, const std::string& target, Module* m, SnortConfig* sc)
{ return new LoggerPiglet(state, target, m, sc); }

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
        "pp_logger",
        "Logger piglet",
        nullptr,
        nullptr
    },
    ctor,
    dtor,
    PT_LOGGER
};

const BaseApi* pp_logger = &piglet_api.base;
