//--------------------------------------------------------------------------
// Copyright (C) 2020-2020 Cisco and/or its affiliates. All rights reserved.
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

// payload_injector_module.h author Maya Dagon <mdagon@cisco.com>

#ifndef PAYLOAD_INJECTOR_MODULE_H
#define PAYLOAD_INJECTOR_MODULE_H

#include "framework/module.h"

namespace snort
{
struct Packet;
}

struct PayloadInjectorCounts
{
    PegCount http_injects;
};

extern THREAD_LOCAL PayloadInjectorCounts payload_injection_stats;

enum InjectionReturnStatus : int8_t
{
    INJECTION_SUCCESS = 1,
    ERR_INJECTOR_NOT_CONFIGURED = -1,
    ERR_STREAM_NOT_ESTABLISHED = -2,
};

struct InjectionControl
{
    const uint8_t* http_page = nullptr;
    uint32_t http_page_len = 0;
};

class SO_PUBLIC PayloadInjectorModule : public snort::Module
{
public:
    PayloadInjectorModule();
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    Usage get_usage() const override
    { return GLOBAL; }

    bool end(const char*, int, snort::SnortConfig*) override;

    static InjectionReturnStatus inject_http_payload(snort::Packet* p, InjectionControl& control);

#ifdef UNIT_TEST
    void set_configured(bool val) { configured = val; }
#endif

private:
    static bool configured;
};

#endif

