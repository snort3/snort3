//--------------------------------------------------------------------------
// Copyright (C) 2020-2025 Cisco and/or its affiliates. All rights reserved.
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

// payload_injector_module.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "payload_injector_module.h"

#include "main/snort_config.h"

#include "payload_injector_config.h"

#define s_name "payload_injector"
#define s_help \
    "payload injection utility"

using namespace snort;

THREAD_LOCAL PayloadInjectorCounts payload_injector_stats;

const PegInfo payload_injector_pegs[] =
{
    { CountType::SUM, "http_injects", "total number of http injections" },
    { CountType::SUM, "http2_injects", "total number of http2 injections" },
    { CountType::SUM, "http2_translate_err", "total number of http2 page translation errors" },
    { CountType::SUM, "http2_mid_frame", "total number of attempts to inject mid-frame" },
    { CountType::END, nullptr, nullptr }
};

PayloadInjectorModule::PayloadInjectorModule() :
    Module(s_name, s_help)
{ }

const PegInfo* PayloadInjectorModule::get_pegs() const
{ return payload_injector_pegs; }

PegCount* PayloadInjectorModule::get_counts() const
{ return (PegCount*)&payload_injector_stats; }

bool PayloadInjectorModule::end(const char*, int, SnortConfig* sc)
{
    assert(sc->payload_injector_config == nullptr);
    sc->payload_injector_config = new PayloadInjectorConfig;
    return true;
}
